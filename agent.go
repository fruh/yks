//go:build linux || darwin

// In-memory cache agent (like ssh-agent, but self-starting and self-stopping).
//
// The first command that derives pk starts "yks __agent" detached (setsid),
// handing it an already-listening Unix socket (fd 3) and the key (stdin).
// Later commands fetch the key over the socket. The agent exits and removes
// its socket when every cached key has expired, or on STOP (`yks forget`).
//
// Protocol, one request per connection:
//
//	GET <id>\n              -> OK\n<32 bytes> | NO\n
//	PUT <id> <ttl>\n<32 B>  -> OK\n
//	DROP <id>\n             -> OK\n
//	STOP\n                  -> OK\n
//
// Both sides verify that the peer runs under the same UID.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxTTL = 24 * 3600

// sockPath returns the agent socket path inside a private per-user directory:
// $XDG_RUNTIME_DIR (Linux, RAM-backed) or $TMPDIR (macOS, already per-user),
// falling back to /tmp. The directory must be ours, mode 0700, not a symlink.
func sockPath() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, fmt.Sprintf("yks-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || !ok || int(st.Uid) != os.Getuid() {
		return "", errors.New("insecure agent directory " + dir)
	}
	return filepath.Join(dir, "agent.sock"), nil
}

// ---------- client ----------

func agentReq(req string, payload []byte) ([]byte, error) {
	path, err := sockPath()
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UnixConn)
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
	if uid, err := peerUID(uc); err != nil || uid != os.Getuid() {
		return nil, errors.New("agent socket is served by another user")
	}
	msg := append([]byte(req+"\n"), payload...)
	_, err = uc.Write(msg)
	clear(msg)
	if err != nil {
		return nil, err
	}
	_ = uc.CloseWrite()
	return io.ReadAll(io.LimitReader(uc, 64))
}

func cacheGet(id string) []byte {
	r, err := agentReq("GET "+id, nil)
	defer clear(r)
	if err != nil || len(r) != 3+32 || string(r[:3]) != "OK\n" {
		return nil
	}
	return append([]byte{}, r[3:]...)
}

func cachePut(id string, key []byte, ttl int) {
	if ttl <= 0 {
		return
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	if _, err := agentReq(fmt.Sprintf("PUT %s %d", id, ttl), key); err == nil {
		return // a running agent took it
	}
	if err := spawnAgent(id, key, ttl); err != nil {
		fmt.Fprintln(os.Stderr, "yks: warning: password cache unavailable:", err)
	}
}

func cacheDrop(id string) { _, _ = agentReq("DROP "+id, nil) }

func agentStop() { _, _ = agentReq("STOP", nil) }

// spawnAgent creates the listening socket itself (so there is no startup race),
// then passes it to a detached child together with the first key.
func spawnAgent(id string, key []byte, ttl int) error {
	path, err := sockPath()
	if err != nil {
		return err
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return errors.New("agent running but not responding")
	}
	_ = os.Remove(path) // stale socket from a crashed agent
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	f, err := ln.File() // dup'ed fd, stays listening after ln.Close
	ln.Close()
	if err != nil {
		os.Remove(path)
		return err
	}
	defer f.Close()
	_ = os.Chmod(path, 0o600)

	exe, err := os.Executable()
	if err != nil {
		os.Remove(path)
		return err
	}
	cmd := exec.Command(exe, "__agent")
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{f} // becomes fd 3 in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		os.Remove(path)
		return err
	}
	if err := cmd.Start(); err != nil {
		os.Remove(path)
		return err
	}
	msg := append([]byte(fmt.Sprintf("%s %d\n", id, ttl)), key...)
	_, _ = in.Write(msg)
	clear(msg)
	_ = in.Close()
	return cmd.Process.Release()
}

// ---------- agent (runs as "yks __agent") ----------

type cached struct {
	key []byte
	exp time.Time
}

type agent struct {
	mu   sync.Mutex
	keys map[string]*cached
	path string
	sock os.FileInfo // our socket file, so we never delete a newer agent's socket
}

func readFields(r *bufio.Reader) []string {
	line, _ := r.ReadString('\n')
	return strings.Fields(line)
}

func runAgent() {
	f := os.NewFile(3, "listener")
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		os.Exit(1)
	}
	ul, ok := l.(*net.UnixListener)
	if !ok {
		os.Exit(1)
	}
	ul.SetUnlinkOnClose(false)
	a := &agent{keys: map[string]*cached{}, path: ul.Addr().String()}
	a.sock, _ = os.Stat(a.path)

	r := bufio.NewReader(os.Stdin)
	if fl := readFields(r); len(fl) == 2 {
		ttl, _ := strconv.Atoi(fl[1])
		key := make([]byte, 32)
		if _, err := io.ReadFull(r, key); err == nil {
			a.put(fl[0], key, ttl)
		}
	}
	os.Stdin.Close()

	go func() {
		for range time.Tick(time.Second) {
			a.expire()
		}
	}()
	for {
		c, err := ul.AcceptUnix()
		if err != nil {
			a.shutdown()
		}
		go a.handle(c)
	}
}

func (a *agent) handle(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if uid, err := peerUID(c); err != nil || uid != os.Getuid() {
		return
	}
	r := bufio.NewReader(io.LimitReader(c, 256))
	fl := readFields(r)
	ok := []byte("OK\n")
	switch {
	case len(fl) == 2 && fl[0] == "GET":
		if k := a.get(fl[1]); k != nil {
			msg := append([]byte("OK\n"), k...)
			_, _ = c.Write(msg)
			clear(msg)
			clear(k)
		} else {
			_, _ = c.Write([]byte("NO\n"))
		}
	case len(fl) == 3 && fl[0] == "PUT":
		ttl, err := strconv.Atoi(fl[2])
		key := make([]byte, 32)
		if _, rerr := io.ReadFull(r, key); err != nil || rerr != nil {
			clear(key)
			return
		}
		a.put(fl[1], key, ttl)
		_, _ = c.Write(ok)
	case len(fl) == 2 && fl[0] == "DROP":
		empty := a.drop(fl[1])
		_, _ = c.Write(ok)
		if empty {
			c.Close()
			a.shutdown()
		}
	case len(fl) == 1 && fl[0] == "STOP":
		_, _ = c.Write(ok)
		c.Close()
		a.shutdown()
	}
}

func (a *agent) put(id string, key []byte, ttl int) {
	if ttl < 1 || ttl > maxTTL {
		ttl = maxTTL
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.keys[id]; ok {
		clear(old.key)
	}
	a.keys[id] = &cached{key: key, exp: time.Now().Add(time.Duration(ttl) * time.Second)}
}

func (a *agent) get(id string) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.keys[id]; ok && time.Now().Before(e.exp) {
		return append([]byte{}, e.key...)
	}
	return nil
}

func (a *agent) drop(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.keys[id]; ok {
		clear(e.key)
		delete(a.keys, id)
	}
	return len(a.keys) == 0
}

func (a *agent) expire() {
	a.mu.Lock()
	now := time.Now()
	for id, e := range a.keys {
		if !now.Before(e.exp) {
			clear(e.key)
			delete(a.keys, id)
		}
	}
	empty := len(a.keys) == 0
	a.mu.Unlock()
	if empty {
		a.shutdown()
	}
}

// shutdown wipes all keys, removes our socket and exits. The lock is never
// released, so concurrent callers simply block until the process is gone.
func (a *agent) shutdown() {
	a.mu.Lock()
	for id, e := range a.keys {
		clear(e.key)
		delete(a.keys, id)
	}
	if fi, err := os.Stat(a.path); err == nil && a.sock != nil && os.SameFile(fi, a.sock) {
		_ = os.Remove(a.path)
	}
	os.Exit(0)
}
