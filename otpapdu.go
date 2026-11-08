//go:build linux || darwin

package main

// The YubiKey's OTP application (the one holding the two challenge-response
// slots) is reachable in two ways: over the USB keyboard interface (HID),
// which is what `ykman otp` uses by default, and over the smart card
// interface (CCID), which is how NFC works and what ykman falls back to.
// This file holds the transport-independent part of talking to it over
// CCID: APDU encoding, the challenge padding, and the status layout.
// Everything here is pure and unit-tested; pcsc_darwin.go does the I/O.
// The byte values come from Yubico's own yubikit (yubiotp.py, core/smartcard).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	otpAID = "\xa0\x00\x00\x05\x27\x20\x01" // the OTP application

	insSelect      = 0xA4
	insConfig      = 0x01 // all OTP slot commands; P1 selects the operation
	insGetResponse = 0xC0 // fetch the rest after SW 61xx

	slotDeviceSerial = 0x10 // P1: read the 4-byte serial
	slotChalHMAC1    = 0x30 // P1: HMAC-SHA1 challenge to slot 1
	slotChalHMAC2    = 0x38 // P1: HMAC-SHA1 challenge to slot 2

	hmacChallengeLen = 64
	hmacResponseLen  = 20

	// config flags in the status, little-endian uint16 at [4:6]
	cfgSlot1Valid = 0x01
	cfgSlot2Valid = 0x02
	cfgSlot1Touch = 0x04
	cfgSlot2Touch = 0x08

	swOK                     = 0x9000
	swConditionsNotSatisfied = 0x6985
)

// errPCSCUnusable marks errors that mean "PC/SC cannot be used for this",
// as opposed to the key itself refusing: no framework, no service, no
// YubiKey reader, the OTP application not selectable. The caller may then
// fall back to ykman. Errors after a successful SELECT are final.
var errPCSCUnusable = errors.New("PC/SC unusable")

// otpStatus is the SELECT response of the OTP application.
type otpStatus struct {
	version [3]byte // firmware
	seq     byte    // programming sequence
	flags   uint16  // cfgSlot* bits
}

func parseOTPStatus(b []byte) (otpStatus, error) {
	if len(b) < 6 {
		return otpStatus{}, fmt.Errorf("short OTP status (%d bytes)", len(b))
	}
	var s otpStatus
	copy(s.version[:], b[:3])
	s.seq = b[3]
	s.flags = binary.LittleEndian.Uint16(b[4:6])
	return s, nil
}

func (s otpStatus) firmware() string {
	return fmt.Sprintf("%d.%d.%d", s.version[0], s.version[1], s.version[2])
}

func (s otpStatus) programmed(slot int) bool {
	if slot == 1 {
		return s.flags&cfgSlot1Valid != 0
	}
	return s.flags&cfgSlot2Valid != 0
}

func (s otpStatus) touch(slot int) bool {
	if slot == 1 {
		return s.flags&cfgSlot1Touch != 0
	}
	return s.flags&cfgSlot2Touch != 0
}

// slotLine describes one slot the way `ykman otp info` does: "Slot 1: programmed".
func (s otpStatus) slotLine(slot int) string {
	switch {
	case !s.programmed(slot):
		return fmt.Sprintf("Slot %d: empty", slot)
	case s.touch(slot):
		return fmt.Sprintf("Slot %d: programmed, touch", slot)
	default:
		return fmt.Sprintf("Slot %d: programmed", slot)
	}
}

// padChallenge pads to 64 bytes exactly like yubikit does, with a byte that
// differs from the last challenge byte so the key can tell where the real
// data ends. This must stay byte-identical to what ykman sends: every entry
// in every store was sealed with the response to the padded challenge.
func padChallenge(c []byte) ([]byte, error) {
	if len(c) > hmacChallengeLen {
		return nil, fmt.Errorf("challenge too long (%d > %d bytes)", len(c), hmacChallengeLen)
	}
	pad := byte(0)
	if len(c) > 0 && c[len(c)-1] == 0 {
		pad = 1
	}
	out := make([]byte, hmacChallengeLen)
	copy(out, c)
	for i := len(c); i < hmacChallengeLen; i++ {
		out[i] = pad
	}
	return out, nil
}

// apdu encodes a short APDU with CLA 00: header, then Lc+data if there is
// data, else an explicit Lc of 0 (as yubikit's ShortApduFormatter does).
func apdu(ins, p1, p2 byte, data []byte) []byte {
	out := []byte{0, ins, p1, p2}
	if len(data) > 0 {
		out = append(out, byte(len(data)))
		return append(out, data...)
	}
	return append(out, 0)
}

// splitSW separates the response data from the trailing status word.
func splitSW(resp []byte) ([]byte, uint16, error) {
	if len(resp) < 2 {
		return nil, 0, fmt.Errorf("short card response (%d bytes)", len(resp))
	}
	n := len(resp) - 2
	return resp[:n], binary.BigEndian.Uint16(resp[n:]), nil
}

// parseMultiString splits a PC/SC multi-string: NUL-separated entries ending
// with an empty one (double NUL).
func parseMultiString(b []byte) []string {
	var out []string
	for _, p := range bytes.Split(b, []byte{0}) {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}

// transmitter sends one raw APDU and returns the raw reply including the
// status word. pcsc_darwin.go implements it; tests use a fake.
type transmitter interface {
	transmit(apdu []byte) ([]byte, error)
}

// sendAPDU sends a command and gathers the reply, following SW 61xx
// ("more data") with GET RESPONSE until the card is done.
func sendAPDU(t transmitter, ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	raw, err := t.transmit(apdu(ins, p1, p2, data))
	if err != nil {
		return nil, 0, err
	}
	resp, sw, err := splitSW(raw)
	if err != nil {
		return nil, 0, err
	}
	for sw>>8 == 0x61 {
		raw, err = t.transmit(apdu(insGetResponse, 0, 0, nil))
		if err != nil {
			return nil, 0, err
		}
		var more []byte
		if more, sw, err = splitSW(raw); err != nil {
			return nil, 0, err
		}
		resp = append(resp, more...)
	}
	return resp, sw, nil
}

// otpSelect selects the OTP application and returns its status. A failure
// here means the application is not reachable over this interface, so the
// error is marked errPCSCUnusable.
func otpSelect(t transmitter) (otpStatus, error) {
	resp, sw, err := sendAPDU(t, insSelect, 0x04, 0x00, []byte(otpAID))
	if err != nil {
		return otpStatus{}, fmt.Errorf("%w: select OTP application: %v", errPCSCUnusable, err)
	}
	if sw != swOK {
		return otpStatus{}, fmt.Errorf("%w: OTP application not available over CCID (SW %04X)", errPCSCUnusable, sw)
	}
	s, err := parseOTPStatus(resp)
	if err != nil {
		return otpStatus{}, fmt.Errorf("%w: %v", errPCSCUnusable, err)
	}
	return s, nil
}

// otpSerial reads the serial number; "" if the key does not report one.
func otpSerial(t transmitter) (string, error) {
	resp, sw, err := sendAPDU(t, insConfig, slotDeviceSerial, 0, nil)
	if err != nil {
		return "", err
	}
	if sw != swOK || len(resp) != 4 {
		return "", nil
	}
	return fmt.Sprint(binary.BigEndian.Uint32(resp)), nil
}

// otpHMAC runs the HMAC-SHA1 challenge-response on a slot. The caller has
// selected the application (so it knows whether to announce a touch).
func otpHMAC(t transmitter, slot int, chal []byte) ([]byte, error) {
	p1 := byte(slotChalHMAC1)
	if slot == 2 {
		p1 = slotChalHMAC2
	}
	padded, err := padChallenge(chal)
	if err != nil {
		return nil, err
	}
	resp, sw, err := sendAPDU(t, insConfig, p1, 0, padded)
	if err != nil {
		return nil, err
	}
	switch {
	case sw == swConditionsNotSatisfied:
		return nil, fmt.Errorf("slot %d: touch timed out or the slot is not configured for challenge-response", slot)
	case sw != swOK:
		return nil, fmt.Errorf("slot %d: challenge-response failed (SW %04X)", slot, sw)
	case len(resp) != hmacResponseLen:
		return nil, fmt.Errorf("slot %d is not configured for HMAC-SHA1 challenge-response (got %d bytes, want %d)", slot, len(resp), hmacResponseLen)
	}
	return resp, nil
}
