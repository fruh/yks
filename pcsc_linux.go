//go:build linux

package main

import "fmt"

// The direct PC/SC backend exists only on macOS, where the system ships
// PCSC.framework. Linux keeps using ykman (pcscd and a C library would be
// needed otherwise, and the static CGO_ENABLED=0 build is worth more).

const pcscBackendName = "PC/SC"

func pcscProbe() error { return fmt.Errorf("%w: built-in backend is macOS only", errPCSCUnusable) }

func pcscListKeys() ([]pcscKey, error) { return nil, pcscProbe() }

func pcscChallenge(string, int, []byte) ([]byte, error) { return nil, pcscProbe() }
