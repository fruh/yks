//go:build linux || darwin

package main

import (
	"errors"
	"strings"
	"testing"
)

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
