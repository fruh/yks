//go:build linux || darwin

package main

// ---------- YubiKey backends ----------
//
// Two ways reach the key's challenge-response slots:
//
//	pcsc   the OTP application over the smart card interface, through the
//	       system PCSC.framework (macOS only; no ykman needed), see pcsc_darwin.go
//	ykman  `ykman otp calculate` over the USB keyboard interface (any
//	       platform; needs YubiKey Manager), see ykman.go
//
// By default PC/SC is used where it works and ykman otherwise; ykman is also
// the fallback when PC/SC sees no key. YKS_BACKEND=pcsc or =ykman forces one.
// Both produce the same response for the same challenge, so stores are
// interchangeable between backends and machines.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func backendMode() string { return os.Getenv("YKS_BACKEND") }

func checkBackendEnv() error {
	switch backendMode() {
	case "", "pcsc", "ykman":
		return nil
	}
	return fmt.Errorf("YKS_BACKEND=%q: must be pcsc or ykman", backendMode())
}

// usePCSC: the built-in backend is the active one.
func usePCSC() bool { return backendMode() != "ykman" && pcscProbe() == nil }

// backendUsable: some backend can talk to a key (modulo it being plugged in).
func backendUsable() bool {
	return usePCSC() || (backendMode() != "pcsc" && haveYkman())
}

// pcscKey is one YubiKey seen over PC/SC. err is set when its OTP
// application could not be reached.
type pcscKey struct {
	reader, serial string
	status         otpStatus
	err            error
}

func (k pcscKey) yubikey() yubikey {
	if k.err != nil {
		return yubikey{desc: "YubiKey [" + k.reader + "]: " + strings.TrimPrefix(k.err.Error(), errPCSCUnusable.Error()+": "), warn: true}
	}
	desc := "YubiKey " + k.status.firmware()
	if k.serial != "" {
		desc += " Serial: " + k.serial
	}
	return yubikey{serial: k.serial, desc: desc + " [" + k.reader + "]"}
}

func pcscToYubikeys(keys []pcscKey) []yubikey {
	out := make([]yubikey, len(keys))
	for i, k := range keys {
		out[i] = k.yubikey()
	}
	return out
}

// slotInfo is what `yks check` shows about one key's OTP slots.
type slotInfo struct {
	text  string
	empty [3]bool // indexed by slot
}

// listYubiKeys enumerates connected keys with the active backend; when
// PC/SC sees none, ykman gets a chance (it also covers the HID interface).
func listYubiKeys() ([]yubikey, error) {
	switch backendMode() {
	case "ykman":
		return ykmanList()
	case "pcsc":
		keys, err := pcscListKeys()
		return pcscToYubikeys(keys), err
	}
	if pcscProbe() == nil {
		keys, err := pcscListKeys()
		if preferPCSCList(keys, err, haveYkman()) {
			return pcscToYubikeys(keys), err
		}
	} else if !haveYkman() {
		return nil, errors.New("ykman: " + hintYkman)
	}
	return ykmanList()
}

// countUsable: PC/SC keys whose OTP application answered.
func countUsable(keys []pcscKey) int {
	n := 0
	for _, k := range keys {
		if k.err == nil {
			n++
		}
	}
	return n
}

// preferPCSCList decides whether the PC/SC listing is the one to show. A
// YubiKey 5 on USB is listed by PC/SC but offers no OTP application there
// (SW 6A82), so when no listed key is usable and ykman exists, ykman's list
// is the truthful one. Without ykman the PC/SC list still shows the reason.
func preferPCSCList(keys []pcscKey, err error, ykman bool) bool {
	return (err == nil && countUsable(keys) > 0) || !ykman
}

// pcscKeyCount reports how many YubiKeys PC/SC lists and how many of them
// answer on the OTP application; (0, 0) when PC/SC is unusable.
func pcscKeyCount() (listed, usable int) {
	keys, err := pcscListKeys()
	if err != nil {
		return 0, 0
	}
	return len(keys), countUsable(keys)
}

const hintInputMonitoring = "On macOS the YubiKey's keyboard (HID) interface, the only way to its slots over USB, " +
	"needs the Input Monitoring permission for your terminal app (System Settings > Privacy & Security > Input Monitoring). " +
	"After granting it, quit and reopen the terminal app; a new window is not enough. " +
	"If no prompt ever appeared, 'tccutil reset ListenEvent' brings it back."

// hidHint adds the macOS explanation when ykman's output shows it could
// not open the YubiKey's HID interface. goos is a parameter for testing.
func hidHint(err error, output, goos string) error {
	if err == nil || goos != "darwin" {
		return err
	}
	if !strings.Contains(output, "Failed opening device") && !strings.Contains(output, "Failed to connect to the device") {
		return err
	}
	return fmt.Errorf("%w\n  ykman could not open the YubiKey's keyboard interface. %s", err, hintInputMonitoring)
}

// pcscSlotInfo reads the slot status of the key with serial dev ("" = the only one).
func pcscSlotInfo(dev string) (slotInfo, error) {
	keys, err := pcscListKeys()
	if err != nil {
		return slotInfo{}, err
	}
	var k *pcscKey
	for i := range keys {
		if (dev == "" && len(keys) == 1) || (dev != "" && keys[i].serial == dev) {
			k = &keys[i]
		}
	}
	if k == nil {
		return slotInfo{}, fmt.Errorf("%w: YubiKey not found", errPCSCUnusable)
	}
	if k.err != nil {
		return slotInfo{}, k.err
	}
	info := slotInfo{text: k.status.slotLine(1) + " | " + k.status.slotLine(2)}
	info.empty[1], info.empty[2] = !k.status.programmed(1), !k.status.programmed(2)
	return info, nil
}

// otpSlots describes the OTP slots of one key, for `yks check`.
func otpSlots(dev string) (slotInfo, error) {
	switch backendMode() {
	case "ykman":
		return ykmanSlotInfo(dev)
	case "pcsc":
		return pcscSlotInfo(dev)
	}
	var perr error
	if pcscProbe() == nil {
		info, err := pcscSlotInfo(dev)
		if err == nil || !errors.Is(err, errPCSCUnusable) || !haveYkman() {
			return info, err
		}
		perr = err
	} else if !haveYkman() {
		return slotInfo{}, errors.New("ykman: " + hintYkman)
	}
	info, err := ykmanSlotInfo(dev)
	if err != nil && perr != nil {
		err = fmt.Errorf("%v; ykman: %w", perr, err)
	}
	return info, err
}

// challengeResponse is the HMAC-SHA1 challenge-response on a slot of the
// YubiKey dev ("" = YKS_DEVICE / .config / the only one; asks if several).
func challengeResponse(slot int, chal []byte, dev string) ([]byte, error) {
	if dev == "" {
		d, err := device()
		if err != nil {
			return nil, err
		}
		dev = d
	}
	switch backendMode() {
	case "ykman":
		return ykmanChallenge(slot, chal, dev)
	case "pcsc":
		return pcscChallenge(dev, slot, chal)
	}
	var perr error
	if pcscProbe() == nil {
		resp, err := pcscChallenge(dev, slot, chal)
		if err == nil || !errors.Is(err, errPCSCUnusable) {
			return resp, err // the key answered (or refused); ykman would get the same
		}
		perr = err
	}
	if !haveYkman() {
		if perr != nil {
			return nil, fmt.Errorf("%v; ykman is not installed, and a YubiKey on USB needs it: %s", perr, hintYkman)
		}
		return nil, errors.New("ykman: " + hintYkman)
	}
	resp, err := ykmanChallenge(slot, chal, dev)
	if err != nil && perr != nil {
		err = fmt.Errorf("%v; %w", perr, err)
	}
	return resp, err
}
