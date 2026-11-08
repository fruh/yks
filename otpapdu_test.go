//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestPadChallenge(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		pad  byte
	}{
		{"normal", bytes.Repeat([]byte{0xAB}, 32), 0x00},
		{"ends in zero", append(bytes.Repeat([]byte{0xAB}, 31), 0x00), 0x01},
		{"empty", nil, 0x00},
	}
	for _, c := range cases {
		out, err := padChallenge(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(out) != 64 || !bytes.Equal(out[:len(c.in)], c.in) {
			t.Fatalf("%s: bad prefix/length: %x", c.name, out)
		}
		for _, b := range out[len(c.in):] {
			if b != c.pad {
				t.Fatalf("%s: pad byte %#x, want %#x", c.name, b, c.pad)
			}
		}
	}
	full := bytes.Repeat([]byte{1}, 64)
	if out, err := padChallenge(full); err != nil || !bytes.Equal(out, full) {
		t.Fatalf("64-byte challenge must pass through unchanged: %v", err)
	}
	if _, err := padChallenge(make([]byte, 65)); err == nil {
		t.Fatal("65-byte challenge must be rejected")
	}
}

func TestAPDU(t *testing.T) {
	sel := apdu(insSelect, 0x04, 0x00, []byte(otpAID))
	want := []byte{0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}
	if !bytes.Equal(sel, want) {
		t.Fatalf("SELECT = % X, want % X", sel, want)
	}
	if got := apdu(insConfig, slotDeviceSerial, 0, nil); !bytes.Equal(got, []byte{0, 1, 0x10, 0, 0}) {
		t.Fatalf("serial APDU = % X", got)
	}
	chal := apdu(insConfig, slotChalHMAC2, 0, make([]byte, 64))
	if len(chal) != 5+64 || chal[2] != 0x38 || chal[4] != 0x40 {
		t.Fatalf("challenge APDU header = % X", chal[:5])
	}
}

func TestParseOTPStatus(t *testing.T) {
	// fw 5.1.2, seq 3, flags: slot1 valid+touch, slot2 valid
	s, err := parseOTPStatus([]byte{5, 1, 2, 3, 0x07, 0x00, 0xFF})
	if err != nil {
		t.Fatal(err)
	}
	if s.firmware() != "5.1.2" || s.seq != 3 {
		t.Fatalf("version/seq: %+v", s)
	}
	if !s.programmed(1) || !s.touch(1) || !s.programmed(2) || s.touch(2) {
		t.Fatalf("flags: %+v", s)
	}
	if s.slotLine(1) != "Slot 1: programmed, touch" || s.slotLine(2) != "Slot 2: programmed" {
		t.Fatalf("lines: %q %q", s.slotLine(1), s.slotLine(2))
	}
	if (otpStatus{}).slotLine(2) != "Slot 2: empty" {
		t.Fatal("empty slot line")
	}
	if _, err := parseOTPStatus([]byte{5, 1, 2}); err == nil {
		t.Fatal("short status must fail")
	}
}

func TestParseMultiString(t *testing.T) {
	got := parseMultiString([]byte("Yubico YubiKey OTP+FIDO+CCID\x00Other Reader 01\x00\x00"))
	if len(got) != 2 || got[0] != "Yubico YubiKey OTP+FIDO+CCID" || got[1] != "Other Reader 01" {
		t.Fatalf("got %q", got)
	}
	if len(parseMultiString([]byte{0})) != 0 || len(parseMultiString(nil)) != 0 {
		t.Fatal("empty multi-string must give no readers")
	}
}

// fakeCard answers each APDU from a script, in order.
type fakeCard struct {
	t     *testing.T
	sent  [][]byte
	reply [][]byte
}

func (f *fakeCard) transmit(a []byte) ([]byte, error) {
	f.sent = append(f.sent, append([]byte{}, a...))
	if len(f.reply) == 0 {
		return nil, errors.New("fake: no reply scripted")
	}
	r := f.reply[0]
	f.reply = f.reply[1:]
	return r, nil
}

func TestSendAPDUChaining(t *testing.T) {
	f := &fakeCard{reply: [][]byte{
		{1, 2, 0x61, 0x03},
		{3, 4, 5, 0x90, 0x00},
	}}
	resp, sw, err := sendAPDU(f, insConfig, slotDeviceSerial, 0, nil)
	if err != nil || sw != swOK || !bytes.Equal(resp, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("resp=% X sw=%04X err=%v", resp, sw, err)
	}
	if len(f.sent) != 2 || !bytes.Equal(f.sent[1], []byte{0, 0xC0, 0, 0, 0}) {
		t.Fatalf("GET RESPONSE not sent: % X", f.sent)
	}
}

func TestOTPSelect(t *testing.T) {
	f := &fakeCard{reply: [][]byte{{5, 4, 3, 0, 0x03, 0x00, 0x90, 0x00}}}
	s, err := otpSelect(f)
	if err != nil || s.firmware() != "5.4.3" || !s.programmed(1) || !s.programmed(2) {
		t.Fatalf("%+v %v", s, err)
	}
	f = &fakeCard{reply: [][]byte{{0x6A, 0x82}}}
	if _, err := otpSelect(f); !errors.Is(err, errPCSCUnusable) {
		t.Fatalf("applet not found must be errPCSCUnusable, got %v", err)
	}
}

func TestOTPSerial(t *testing.T) {
	f := &fakeCard{reply: [][]byte{{0x00, 0x89, 0xCE, 0xF2, 0x90, 0x00}}} // 0x0089CEF2 = 9031410
	if s, err := otpSerial(f); err != nil || s != "9031410" {
		t.Fatalf("serial %q %v", s, err)
	}
	f = &fakeCard{reply: [][]byte{{0x90, 0x00}}}
	if s, err := otpSerial(f); err != nil || s != "" {
		t.Fatalf("no serial: %q %v", s, err)
	}
}

func TestOTPHMAC(t *testing.T) {
	resp20 := bytes.Repeat([]byte{0xEE}, 20)
	f := &fakeCard{reply: [][]byte{append(append([]byte{}, resp20...), 0x90, 0x00)}}
	chal := bytes.Repeat([]byte{7}, 32)
	got, err := otpHMAC(f, 2, chal)
	if err != nil || !bytes.Equal(got, resp20) {
		t.Fatalf("%x %v", got, err)
	}
	if a := f.sent[0]; a[1] != insConfig || a[2] != slotChalHMAC2 || a[4] != 64 || !bytes.Equal(a[5:5+32], chal) {
		t.Fatalf("challenge APDU = % X", a)
	}
	for _, b := range f.sent[0][5+32:] {
		if b != 0 {
			t.Fatal("padding must be zero for a challenge not ending in zero")
		}
	}
	f = &fakeCard{reply: [][]byte{{0x69, 0x85}}}
	if _, err := otpHMAC(f, 1, chal); err == nil || errors.Is(err, errPCSCUnusable) {
		t.Fatalf("touch timeout must be a final error, got %v", err)
	}
	f = &fakeCard{reply: [][]byte{{1, 2, 3, 0x90, 0x00}}}
	if _, err := otpHMAC(f, 1, chal); err == nil || errors.Is(err, errPCSCUnusable) {
		t.Fatalf("wrong length must be a final error, got %v", err)
	}
}
