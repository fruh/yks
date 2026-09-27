//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Which YubiKey to use, in order of precedence:
//   1. -d / --device SERIAL on the command line
//   2. YKS_DEVICE environment variable
//   3. device=SERIAL in the store's .config
//   4. the only connected YubiKey
//   5. ask, when several are connected (once per command)

var flagDevice string // set from -d / --device

type yubikey struct {
	serial string // empty if the key does not report one
	desc   string // the line from `ykman list`
}

var serialRe = regexp.MustCompile(`Serial:\s*(\d+)`)

func validSerial(s string) bool {
	if s == "" || len(s) > 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func listYubiKeys() ([]yubikey, error) {
	out, err := exec.Command("ykman", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("ykman list failed: %w", err)
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

// defaultDevice returns the configured device (flag, env, .config) and where
// it came from, without talking to any YubiKey. "" means none is configured.
func defaultDevice() (serial, source string) {
	if flagDevice != "" {
		return flagDevice, "-d"
	}
	if d := os.Getenv("YKS_DEVICE"); d != "" {
		return d, "YKS_DEVICE"
	}
	if c, err := loadConfig(); err == nil && c.Device != "" {
		return c.Device, ".config"
	}
	return "", ""
}

var (
	resolvedDevice string
	deviceResolved bool
)

// device returns the serial to pass to ykman ("" = the only connected key).
// With several keys connected and no default, it asks once per command.
func device() (string, error) {
	if deviceResolved {
		return resolvedDevice, nil
	}
	d, src := defaultDevice()
	if d != "" && !validSerial(d) {
		return "", fmt.Errorf("invalid YubiKey serial %q (from %s)", d, src)
	}
	if d == "" {
		keys, err := listYubiKeys()
		if err != nil {
			return "", err
		}
		switch len(keys) {
		case 0:
			return "", errors.New("no YubiKey detected: plug one in")
		case 1: // ykman picks it; no --device needed
		default:
			if d, err = pickYubiKey(keys, false); err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "tip: skip this question with -d %s, YKS_DEVICE=%s, or device=%s in %s\n",
				d, d, d, configPath())
		}
	}
	resolvedDevice, deviceResolved = d, true
	return d, nil
}

// pickYubiKey asks which of several connected keys to use. With optional,
// Enter returns "" (no choice) instead of cancelling.
func pickYubiKey(keys []yubikey, optional bool) (string, error) {
	var usable []yubikey
	for _, k := range keys {
		if k.serial != "" {
			usable = append(usable, k)
		}
	}
	if len(usable) == 0 {
		return "", errors.New("several YubiKeys are connected but none reports a serial number: unplug all but one")
	}
	items := make([]string, len(usable))
	for i, k := range usable {
		items[i] = k.desc
	}
	what := "YubiKey"
	if optional {
		what = "Default YubiKey (Enter for none)"
	}
	i, err := pickFrom("Several YubiKeys are connected:", items, what, optional)
	if err != nil || i < 0 {
		return "", err
	}
	return usable[i].serial, nil
}
