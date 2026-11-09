//go:build linux || darwin

package main

// Talking to the YubiKey: everything that shells out to YubiKey Manager.
// ykman reaches the challenge-response slots over the key's USB keyboard
// (HID) interface, the only interface on which a YubiKey 5 performs them.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// exitStderrAll returns everything a failed command wrote to stderr.
func exitStderrAll(err error) []byte {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.Stderr
	}
	return nil
}

const hintYkman = "install YubiKey Manager: 'brew install ykman' (macOS), 'apt install yubikey-manager' (Debian/Ubuntu), 'dnf install yubikey-manager' (Fedora), 'pacman -S yubikey-manager' (Arch)"

func haveYkman() bool { _, err := exec.LookPath("ykman"); return err == nil }

// ykman builds an ykman command that needs no particular YubiKey.
func ykman(args ...string) *exec.Cmd { return ykmanOn("", args...) }

// ykmanOn targets the YubiKey with serial dev ("" = let ykman choose).
func ykmanOn(dev string, args ...string) *exec.Cmd {
	if dev != "" {
		args = append([]string{"--device", dev}, args...)
	}
	return exec.Command("ykman", args...)
}

var (
	respRe   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
	promptRe = regexp.MustCompile(`Enter a challenge[^:\n]*:\s?`)
	serialRe = regexp.MustCompile(`Serial:\s*(\d+)`)
)

// exitStderr returns what a failed command wrote to stderr (captured by
// Output), trimmed to its last line.
func exitStderr(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		lines := strings.Split(strings.TrimSpace(string(ee.Stderr)), "\n")
		return strings.TrimSpace(lines[len(lines)-1])
	}
	return ""
}

// listYubiKeys parses `ykman list`.
func listYubiKeys() ([]yubikey, error) {
	out, err := exec.Command("ykman", "list").Output()
	if err != nil {
		if s := exitStderr(err); s != "" {
			err = fmt.Errorf("%w: %s", err, s)
		}
		return nil, hidHint(fmt.Errorf("ykman list failed: %w", err), string(exitStderrAll(err)), runtime.GOOS)
	}
	var keys []yubikey
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		k := yubikey{desc: l}
		if m := serialRe.FindStringSubmatch(l); m != nil {
			k.serial = m[1]
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// slotInfo is what `yks check` shows about one key's OTP slots.
type slotInfo struct {
	text  string
	empty [3]bool // indexed by slot
}

// otpSlots parses `ykman otp info` ("Slot 1: programmed", "Slot 2: empty").
func otpSlots(dev string) (slotInfo, error) {
	out, err := ykmanOn(dev, "otp", "info").CombinedOutput()
	text := strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " | ")), " ")
	if err != nil {
		return slotInfo{}, hidHint(errors.New(text), text, runtime.GOOS)
	}
	info := slotInfo{text: text}
	for _, l := range strings.Split(string(out), "\n") {
		for slot := 1; slot <= 2; slot++ {
			if strings.HasPrefix(l, fmt.Sprintf("Slot %d:", slot)) && strings.Contains(l, "empty") {
				info.empty[slot] = true
			}
		}
	}
	return info, nil
}

// challengeResponse runs `ykman [--device SERIAL] otp calculate <slot>` on
// the YubiKey dev ("" = YKS_DEVICE / .config / the only one; asks if several)
// and writes the challenge to its stdin, where ykman's challenge prompt reads
// it. Nothing secret-derived appears in the process list (ps, /proc/<pid>/cmdline).
// YKS_CHALLENGE_ARG=1 passes the challenge as an argument instead, for ykman
// versions that cannot read it from stdin. That exposure is harmless in this
// design (the challenge is a one-way function of pk) but avoided by default.
func challengeResponse(slot int, chal []byte, dev string) ([]byte, error) {
	if dev == "" {
		d, err := device()
		if err != nil {
			return nil, err
		}
		dev = d
	}
	hexChal := hex.EncodeToString(chal)
	args := []string{"otp", "calculate", strconv.Itoa(slot)}
	viaArg := os.Getenv("YKS_CHALLENGE_ARG") == "1"
	if viaArg {
		args = append(args, hexChal)
	}
	cmd := ykmanOn(dev, args...)
	if !viaArg {
		cmd.Stdin = strings.NewReader(hexChal + "\n")
	}
	// Show ykman's "Touch your YubiKey..." but not its challenge prompt;
	// keep a copy to explain a failure.
	var errOut bytes.Buffer
	cmd.Stderr = io.MultiWriter(promptFilter{os.Stderr}, &errOut)
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("ykman otp calculate failed (slot %d configured for challenge-response?): %w", slot, err)
		return nil, hidHint(err, errOut.String(), runtime.GOOS)
	}
	// The response is the last 40-hex-digit word; a prompt may precede it.
	m := respRe.FindAllString(string(out), -1)
	if len(m) == 0 {
		hint := ""
		if !viaArg {
			hint = "; if your ykman cannot read the challenge from stdin, set YKS_CHALLENGE_ARG=1"
		}
		return nil, errors.New("no response in ykman output (expected 40 hex characters)" + hint)
	}
	return hex.DecodeString(m[len(m)-1])
}

// promptFilter removes ykman's "Enter a challenge (hex):" prompt from its
// stderr and passes everything else through.
type promptFilter struct{ w io.Writer }

func (f promptFilter) Write(p []byte) (int, error) {
	if _, err := f.w.Write(promptRe.ReplaceAll(p, nil)); err != nil {
		return 0, err
	}
	return len(p), nil
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
