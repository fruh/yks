//go:build darwin

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// harden: no core dumps; refuse debugger attachment (PT_DENY_ATTACH).
func harden() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	_ = unix.PtraceDenyAttach()
}

// peerUID returns the UID of the process on the other end of the socket.
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid, serr := -1, error(nil)
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			serr = e
			return
		}
		uid = int(cred.Uid)
	}); err != nil {
		return -1, err
	}
	return uid, serr
}
