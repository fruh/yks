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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
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
			pcscDebugf("dlopen %s: %v", pcscFramework, err)
			pcscLoadErr = fmt.Errorf("%w: %v", errPCSCUnusable, err)
			return
		}
		pcscDebugf("loaded %s", pcscFramework)
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

var pcscErrText = map[uint32]string{
	0x80100006: "insufficient buffer",
	0x80100009: "unknown reader",
	0x8010000A: "timeout",
	0x8010000B: "sharing violation: another program holds the YubiKey's smart card interface. " +
		"Usual suspects: GnuPG's scdaemon (run 'gpgconf --kill scdaemon', or put 'pcsc-shared' in ~/.gnupg/scdaemon.conf), " +
		"Yubico Authenticator, or a browser; quit it and retry",
	0x8010000C: "no smart card (YubiKey removed)",
	0x8010000F: "protocol mismatch",
	0x80100016: "not transacted",
	0x80100017: "reader unavailable",
	0x8010001D: "smart card service not running",
	0x8010002E: "no readers available",
	0x80100065: "unsupported card",
	0x80100066: "unresponsive card",
	0x80100067: "unpowered card",
	0x80100068: "card was reset",
	0x80100069: "card removed",
}

func pcscErr(op string, rc uint32) error {
	if t, ok := pcscErrText[rc]; ok {
		return fmt.Errorf("%s: %s (PC/SC 0x%08X)", op, t, rc)
	}
	return fmt.Errorf("%s: PC/SC error 0x%08X", op, rc)
}

// YKS_DEBUG=1 traces the PC/SC calls on stderr. Challenge and response
// bytes are never printed: they derive from the master password.
var pcscDebug = os.Getenv("YKS_DEBUG") == "1"

func pcscDebugf(format string, a ...any) {
	if pcscDebug {
		fmt.Fprintf(os.Stderr, "yks pcsc: "+format+"\n", a...)
	}
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
		pcscDebugf("SCardEstablishContext: 0x%08X", rc)
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardEstablishContext", rc))
	}
	pcscDebugf("SCardEstablishContext ok")
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
		yk := strings.Contains(strings.ToLower(r), ykReaderName)
		pcscDebugf("reader %q (YubiKey: %v)", r, yk)
		if yk {
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
	var rc uint32
	// Other programs (scdaemon, Yubico Authenticator) hold the card only
	// while they talk to it; a few short retries often get in between.
	for attempt := 0; ; attempt++ {
		rc = c.l.connect(c.h, &name[0], scardShareShared, scardProtocolT0|scardProtocolT1, &h, &proto)
		if rc != scardESharingViolation || attempt == 5 {
			break
		}
		pcscDebugf("SCardConnect %q: sharing violation, retrying", reader)
		time.Sleep(200 * time.Millisecond)
	}
	if rc != 0 {
		pcscDebugf("SCardConnect %q: 0x%08X", reader, rc)
		return nil, fmt.Errorf("%w: %v", errPCSCUnusable, pcscErr("SCardConnect", rc))
	}
	pcscDebugf("SCardConnect %q ok, protocol T=%d", reader, proto-1)
	card := &pcscCard{c.l, h, scardIORequest{proto, uint32(unsafe.Sizeof(scardIORequest{}))}}
	if rc = c.l.beginTransaction(h); rc != 0 {
		pcscDebugf("SCardBeginTransaction: 0x%08X", rc)
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
	if pcscDebug {
		if len(a) >= 4 && a[1] == insConfig && (a[2] == slotChalHMAC1 || a[2] == slotChalHMAC2) {
			pcscDebugf("-> % X ... (%d bytes, challenge not shown)", a[:4], len(a))
		} else {
			pcscDebugf("-> % X", a)
		}
	}
	recv := make([]byte, 258) // 256 data + SW
	n := uint32(len(recv))
	rc := c.l.transmit(c.h, &c.pci, &a[0], uint32(len(a)), nil, &recv[0], &n)
	if rc != 0 {
		pcscDebugf("SCardTransmit: 0x%08X", rc)
		return nil, pcscErr("SCardTransmit", rc)
	}
	if pcscDebug && n >= 2 {
		pcscDebugf("<- %d bytes, SW %02X%02X", n-2, recv[n-2], recv[n-1])
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
		pcscDebugf("%q: %v", reader, err)
		return "", otpStatus{}, err
	}
	serial, err := otpSerial(card)
	pcscDebugf("%q: firmware %s, serial %q, %s, %s", reader, st.firmware(), serial, st.slotLine(1), st.slotLine(2))
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
