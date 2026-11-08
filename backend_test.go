//go:build linux || darwin

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestPreferPCSCList(t *testing.T) {
	usable := pcscKey{reader: "r", serial: "1"}
	broken := pcscKey{reader: "r", err: errors.New("SW 6A82")}
	cases := []struct {
		name  string
		keys  []pcscKey
		err   error
		ykman bool
		want  bool
	}{
		{"usable key, ykman present", []pcscKey{usable}, nil, true, true},
		{"usable key, no ykman", []pcscKey{usable}, nil, false, true},
		{"USB key (no OTP over CCID), ykman present: ykman's list", []pcscKey{broken}, nil, true, false},
		{"USB key, no ykman: show the reason", []pcscKey{broken}, nil, false, true},
		{"mixed: PC/SC list", []pcscKey{broken, usable}, nil, true, true},
		{"no key, ykman present: let ykman look", nil, nil, true, false},
		{"no key, no ykman", nil, nil, false, true},
		{"listing error, ykman present", nil, errors.New("boom"), true, false},
	}
	for _, c := range cases {
		if got := preferPCSCList(c.keys, c.err, c.ykman); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHidHint(t *testing.T) {
	base := errors.New("ykman otp calculate failed: exit status 1")
	if err := hidHint(base, "WARNING: Failed opening device", "darwin"); err == nil ||
		!errors.Is(err, base) || !strings.Contains(err.Error(), "Input Monitoring") || !strings.Contains(err.Error(), "quit and reopen") {
		t.Fatalf("darwin + HID failure must explain Input Monitoring: %v", err)
	}
	if err := hidHint(base, "ERROR: Failed to connect to the device", "darwin"); !strings.Contains(err.Error(), "Input Monitoring") {
		t.Fatalf("second ykman phrase: %v", err)
	}
	if err := hidHint(base, "WARNING: Failed opening device", "linux"); err != base {
		t.Fatalf("linux must be untouched: %v", err)
	}
	if err := hidHint(base, "touch timed out", "darwin"); err != base {
		t.Fatalf("other failures must be untouched: %v", err)
	}
	if err := hidHint(nil, "WARNING: Failed opening device", "darwin"); err != nil {
		t.Fatalf("nil stays nil: %v", err)
	}
}
