//go:build darwin

package main

// Direct access to the YubiKey over the smart card interface (CCID) through
// macOS's own PCSC.framework. The framework is loaded at run time with purego,
// so the binary stays cgo-free and still cross-compiles from Linux. Types
// follow Apple's wintypes.h, where LONG and DWORD are 32 bits, and so are
// SCARDCONTEXT and SCARDHANDLE.
//
// Why: ykman reaches the OTP slots over the USB keyboard interface (HID),
// which macOS guards with the Input Monitoring permission and which other
// apps can hold; "WARNING: Failed opening device" is that path failing. The
// same slots answer over CCID, which needs neither.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	pcscFramework   = "/System/Library/Frameworks/PCSC.framework/PCSC"
	pcscBackendName = "PC/SC (PCSC.framework)"
	ykReaderName    = "yubico yubikey" // ykman's reader filter, case-insensitive

	scardScopeSystem = 2
	scardShareShared = 2
	scardProtocolT0  = 1
	scardProtocolT1  = 2
	scardLeaveCard   = 0

	scardESharingViolation   = 0x8010000B
	scardENoSmartcard        = 0x8010000C
	scardENoService          = 0x8010001D
	scardENoReadersAvailable = 0x8010002E
	scardWRemovedCard        = 0x80100069
)

type scardIORequest struct {
	protocol  uint32
	pciLength uint32
}

type pcscLib struct {
	establishContext func(scope uint32, r1, r2 uintptr, ctx *int32) uint32
	releaseContext   func(ctx int32) uint32
	listReaders      func(ctx int32, groups *byte, readers *byte, n *uint32) uint32
	connect          func(ctx int32, reader *byte, share, protocols uint32, card *int32, active *uint32) uint32
	disconnect       func(card int32, disposition uint32) uint32
	beginTransaction func(card int32) uint32
	endTransaction   func(card int32, disposition uint32) uint32
	transmit         func(card int32, sendPci *scardIORequest, send *byte, sendLen uint32,
		recvPci *scardIORequest, recv *byte, recvLen *uint32) uint32
}

var (
	pcscOnce    sync.Once
	pcscL       *pcscLib
	pcscLoadErr error
)

func pcscLoad() (*pcscLib, error) {
	pcscOnce.Do(func() {
		defer func() { // RegisterLibFunc panics on a missing symbol
			if r := recover(); r != nil {
				pcscLoadErr = fmt.Errorf("%w: %v", errPCSCUnusable, r)
			}
		}()
		h, err := purego.Dlopen(pcscFramework, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			pcscLoadErr = fmt.Errorf("%w: %v", errPCSCUnusable, err)
			return
		}
		l := &pcscLib{}
		purego.RegisterLibFunc(&l.establishContext, h, "SCardEstablishContext")
		purego.RegisterLibFunc(&l.releaseContext, h, "SCardReleaseContext")
		purego.RegisterLibFunc(&l.listReaders, h, "SCardListReaders")
		purego.RegisterLibFunc(&l.connect, h, "SCardConnect")
		purego.RegisterLibFunc(&l.disconnect, h, "SCardDisconnect")
		purego.RegisterLibFunc(&l.beginTransaction, h, "SCardBeginTransaction")
		purego.RegisterLibFunc(&l.endTransaction, h, "SCardEndTransaction")
		purego.RegisterLibFunc(&l.transmit, h, "SCardTransmit")
		pcscL = l
	})
	return pcscL, pcscLoadErr
}

func pcscErr(op string, rc uint32) error {
	msg := fmt.Sprintf("%s: PC/SC error 0x%08X", op, rc)
	switch rc {
	case scardENoService:
		msg += " (smart card service not running)"
	case scardESharingViolation:
		msg += " (another application holds the YubiKey; close Yubico Authenticator or similar and retry)"
	case scardWRemovedCard, scardENoSmartcard:
		msg += " (YubiKey removed)"
	}
	return errors.New(msg)
}

var (
	pcscProbeOnce sync.Once
	pcscProbeErr  error
)

// pcscProbe reports whether PC/SC can be used at all: the framework loads
// and a context can be established. It says nothing about connected keys.
func pcscProbe() error {
	pcscProbeOnce.Do(func() {
		ctx, err := pcscOpen()
		if err != nil {
			pcscProbeErr = err
			return
		}
		ctx.close()
	})
	return pcscProbeErr
}

type pcscCtx struct {
	l *pcscLib
	h int32
}

func pcscOpen() (*pcscCtx, error) {
	l, err := pcscLoad()
	if err != nil {
		return nil, err
	}
	var h int32
	if rc := l.establishContext(scardScopeSystem, 0, 0, &h); rc != 0 {
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardEstablishContext", rc))
	}
	return &pcscCtx{l, h}, nil
}

func (c *pcscCtx) close() { c.l.releaseContext(c.h) }

// yubikeyReaders lists the connected readers that are YubiKeys.
func (c *pcscCtx) yubikeyReaders() ([]string, error) {
	var n uint32
	rc := c.l.listReaders(c.h, nil, nil, &n)
	if rc == scardENoReadersAvailable || (rc == 0 && n == 0) {
		return nil, nil
	}
	if rc != 0 {
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardListReaders", rc))
	}
	buf := make([]byte, n)
	if rc = c.l.listReaders(c.h, nil, &buf[0], &n); rc != 0 {
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardListReaders", rc))
	}
	var out []string
	for _, r := range parseMultiString(buf[:n]) {
		if strings.Contains(strings.ToLower(r), ykReaderName) {
			out = append(out, r)
		}
	}
	return out, nil
}

type pcscCard struct {
	l   *pcscLib
	h   int32
	pci scardIORequest
}

// connect opens a shared connection and starts a transaction, so nobody
// else can change the selected application between our commands.
func (c *pcscCtx) connect(reader string) (*pcscCard, error) {
	name := append([]byte(reader), 0)
	var h int32
	var proto uint32
	rc := c.l.connect(c.h, &name[0], scardShareShared, scardProtocolT0|scardProtocolT1, &h, &proto)
	if rc != 0 {
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardConnect", rc))
	}
	card := &pcscCard{c.l, h, scardIORequest{proto, uint32(unsafe.Sizeof(scardIORequest{}))}}
	if rc = c.l.beginTransaction(h); rc != 0 {
		card.l.disconnect(h, scardLeaveCard)
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardBeginTransaction", rc))
	}
	return card, nil
}

func (c *pcscCard) close() {
	c.l.endTransaction(c.h, scardLeaveCard)
	c.l.disconnect(c.h, scardLeaveCard)
}

// transmit implements transmitter: one APDU, raw reply including the SW.
func (c *pcscCard) transmit(a []byte) ([]byte, error) {
	recv := make([]byte, 258) // 256 data + SW
	n := uint32(len(recv))
	rc := c.l.transmit(c.h, &c.pci, &a[0], uint32(len(a)), nil, &recv[0], &n)
	if rc != 0 {
		return nil, pcscErr("SCardTransmit", rc)
	}
	return recv[:n], nil
}

// probe connects to one reader and reads the OTP status and serial.
func (c *pcscCtx) probe(reader string) (string, otpStatus, error) {
	card, err := c.connect(reader)
	if err != nil {
		return "", otpStatus{}, err
	}
	defer card.close()
	st, err := otpSelect(card)
	if err != nil {
		return "", otpStatus{}, err
	}
	serial, err := otpSerial(card)
	return serial, st, err
}

// pcscListKeys enumerates the connected YubiKeys. A key whose OTP
// application cannot be reached is still listed, with err set.
func pcscListKeys() ([]pcscKey, error) {
	ctx, err := pcscOpen()
	if err != nil {
		return nil, err
	}
	defer ctx.close()
	readers, err := ctx.yubikeyReaders()
	if err != nil {
		return nil, err
	}
	var keys []pcscKey
	for _, r := range readers {
		k := pcscKey{reader: r}
		k.serial, k.status, k.err = ctx.probe(r)
		keys = append(keys, k)
	}
	return keys, nil
}

// pcscChallenge runs the HMAC-SHA1 challenge-response on the key with the
// given serial ("" = the only connected one).
func pcscChallenge(serial string, slot int, chal []byte) ([]byte, error) {
	ctx, err := pcscOpen()
	if err != nil {
		return nil, err
	}
	defer ctx.close()
	readers, err := ctx.yubikeyReaders()
	if err != nil {
		return nil, err
	}
	var reader string
	switch {
	case len(readers) == 0:
		return nil, fmt.Errorf("%w: no YubiKey detected", errPCSCUnusable)
	case serial == "" && len(readers) > 1:
		return nil, fmt.Errorf("%w: several YubiKeys are connected", errPCSCUnusable)
	case serial == "":
		reader = readers[0]
	default:
		for _, r := range readers {
			if s, _, err := ctx.probe(r); err == nil && s == serial {
				reader = r
				break
			}
		}
		if reader == "" {
			return nil, fmt.Errorf("%w: YubiKey %s not found", errPCSCUnusable, serial)
		}
	}
	card, err := ctx.connect(reader)
	if err != nil {
		return nil, err
	}
	defer card.close()
	st, err := otpSelect(card)
	if err != nil {
		return nil, err
	}
	// From here on the key itself answers; ykman would get the same answer.
	if !st.programmed(slot) {
		return nil, fmt.Errorf("slot %d is empty; see 'YubiKey setup' in the README", slot)
	}
	if st.touch(slot) {
		fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
	}
	return otpHMAC(card, slot, chal)
}
