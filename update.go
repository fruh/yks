//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const defaultModule = "github.com/fruh/yks"

// modulePath is the module this binary was built from, so forks update from
// their own repository.
func modulePath() string {
	if bi, ok := debug.ReadBuildInfo(); ok && strings.Contains(bi.Main.Path, "/") {
		return bi.Main.Path
	}
	return defaultModule
}

// cmdUpdate builds the requested version with `go install` into a temporary
// directory and then replaces the running binary in place, wherever it is
// installed. Go verifies the downloaded source against the public checksum
// database (sum.golang.org), so a tampered release tag is rejected.
func cmdUpdate(args []string) error {
	version := "latest"
	if len(args) == 1 {
		version = args[0]
	} else if len(args) > 1 {
		usage()
	}
	if version == "" || strings.ContainsAny(version, " \t\n@") || strings.HasPrefix(version, "-") {
		return fmt.Errorf("invalid version %q (use latest, a tag like v1.2.3, a branch or a commit)", version)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return errors.New("updating needs the Go toolchain (https://go.dev/dl/); without it, download or build yks on another machine and copy the binary")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "yks-update-")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(tmp)
		}
	}()

	mod := modulePath()
	cur := versionString()
	fmt.Fprintf(os.Stderr, "current: %s (%s)\nbuilding %s@%s ...\n", cur, exe, mod, version)
	cmd := exec.Command(goBin, "install", "-trimpath", "-ldflags=-s -w", mod+"@"+version)
	cmd.Dir = tmp // outside any module, so the local go.mod cannot interfere
	cmd.Env = append(os.Environ(), "GOBIN="+tmp)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install failed: %w", err)
	}

	newBin := filepath.Join(tmp, filepath.Base(mod))
	out, err := exec.Command(newBin, "version").Output()
	if err != nil {
		return fmt.Errorf("the new binary does not run: %w", err)
	}
	newVer := strings.TrimPrefix(strings.TrimSpace(string(out)), "yks ")
	if newVer == cur && cur != "(devel)" && cur != "unknown" {
		fmt.Fprintf(os.Stderr, "already up to date (%s)\n", cur)
		return nil
	}

	if err := replaceExecutable(exe, newBin); err != nil {
		keep = true
		return fmt.Errorf("cannot replace %s: %v\nthe new version is built; install it with:\n  sudo install -m 0755 %q %q", exe, err, newBin, exe)
	}
	agentStop() // the next command starts an agent from the new binary
	fmt.Fprintf(os.Stderr, "updated %s: %s -> %s\n", exe, cur, newVer)
	return nil
}

// replaceExecutable atomically swaps dst for a copy of src: it writes a
// temporary file next to dst and renames it over dst. The running process
// keeps using the old file until it exits.
func replaceExecutable(dst, src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".yks-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0o755)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), dst)
}
