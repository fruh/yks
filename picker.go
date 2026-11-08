//go:build linux || darwin

package main

// ---------- interactive entry picker ----------
//
// A small filter-as-you-type list on the terminal, in the spirit of fzf but
// written on x/term alone: type to narrow, arrows to move, Enter to choose.
// It draws in place below the shell prompt (no alternate screen) and leaves
// only the "selected: <name>" line behind, like the numbered tree it
// replaces. Everything goes through /dev/tty so stdout stays redirectable.
// The pure parts (matching, key decoding, layout) are unit-tested.

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// chooseEntry asks for one of names (all entries when nil). initial
// pre-fills the picker's filter; header is for the numbered fallback, which
// is used without a terminal, with TERM=dumb, or with YKS_PICKER=plain.
func chooseEntry(names []string, initial, header string) (string, error) {
	if names == nil {
		var err error
		if names, err = listEntries(); err != nil {
			return "", err
		}
		if len(names) == 0 {
			return "", errors.New("store is empty")
		}
	}
	if os.Getenv("YKS_PICKER") != "plain" && os.Getenv("TERM") != "dumb" {
		if t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			if term.IsTerminal(int(t.Fd())) {
				defer t.Close()
				return pickEntry(t, names, initial)
			}
			t.Close()
		}
	}
	if initial != "" {
		names = filterEntries(names, initial)
	}
	return pickTree(names, header)
}

// ----- matching -----

// matchEntries keeps the names containing every space-separated word of
// filter, ignoring case, ranked: exact name, then names whose last path
// component starts with the last word, then the rest; each group keeps the
// incoming (sorted) order.
func matchEntries(names []string, filter string) []string {
	words := strings.Fields(strings.ToLower(filter))
	if len(words) == 0 {
		return names
	}
	q := strings.ToLower(strings.TrimSpace(filter))
	last := words[len(words)-1]
	var exact, base, rest []string
	for _, n := range names {
		ln := strings.ToLower(n)
		ok := true
		for _, w := range words {
			if !strings.Contains(ln, w) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		b := ln
		if i := strings.LastIndexByte(ln, '/'); i >= 0 {
			b = ln[i+1:]
		}
		switch {
		case ln == q:
			exact = append(exact, n)
		case strings.HasPrefix(b, last):
			base = append(base, n)
		default:
			rest = append(rest, n)
		}
	}
	return append(append(exact, base...), rest...)
}

// longestCommonPrefix of names, in runes.
func longestCommonPrefix(names []string) string {
	if len(names) == 0 {
		return ""
	}
	p := []rune(names[0])
	for _, n := range names[1:] {
		r := []rune(n)
		i := 0
		for i < len(p) && i < len(r) && p[i] == r[i] {
			i++
		}
		p = p[:i]
		if len(p) == 0 {
			break
		}
	}
	return string(p)
}

// ----- keys -----

type key int

const (
	keyNone key = iota // nothing usable (unknown sequence, ignored control)
	keyRune            // a printable rune in keyEvent.r
	keyEnter
	keyEsc
	keyCancel // Ctrl-C, Ctrl-D
	keyBackspace
	keyTab
	keyUp
	keyDown
	keyPgUp
	keyPgDn
	keyHome
	keyEnd
	keyCtrlU
	keyCtrlR
)

type keyEvent struct {
	k key
	r rune
}

// decodeKey decodes the first key in b and how many bytes it used.
// used == 0 means b ends in the middle of a sequence: read more first
// (a lone ESC is reported by the caller after a short wait).
func decodeKey(b []byte) (keyEvent, int) {
	if len(b) == 0 {
		return keyEvent{}, 0
	}
	switch b[0] {
	case 0x1b:
		if len(b) == 1 {
			return keyEvent{}, 0
		}
		if b[1] != '[' && b[1] != 'O' {
			return keyEvent{k: keyEsc}, 1 // ESC then another key (Alt-x): just ESC
		}
		// CSI: parameters (digits, ';') then a final byte 0x40-0x7E
		i := 2
		for i < len(b) && (b[i] >= '0' && b[i] <= '9' || b[i] == ';') {
			i++
		}
		if i >= len(b) {
			return keyEvent{}, 0
		}
		param, final := string(b[2:i]), b[i]
		i++
		switch {
		case final == 'A':
			return keyEvent{k: keyUp}, i
		case final == 'B':
			return keyEvent{k: keyDown}, i
		case final == 'H' || final == '~' && (param == "1" || param == "7"):
			return keyEvent{k: keyHome}, i
		case final == 'F' || final == '~' && (param == "4" || param == "8"):
			return keyEvent{k: keyEnd}, i
		case final == '~' && param == "5":
			return keyEvent{k: keyPgUp}, i
		case final == '~' && param == "6":
			return keyEvent{k: keyPgDn}, i
		}
		return keyEvent{}, i // left/right, delete, function keys: ignored
	case '\r', '\n':
		return keyEvent{k: keyEnter}, 1
	case 0x7f, 0x08:
		return keyEvent{k: keyBackspace}, 1
	case '\t':
		return keyEvent{k: keyTab}, 1
	case 0x03, 0x04:
		return keyEvent{k: keyCancel}, 1
	case 0x15:
		return keyEvent{k: keyCtrlU}, 1
	case 0x12:
		return keyEvent{k: keyCtrlR}, 1
	case 0x10:
		return keyEvent{k: keyUp}, 1 // Ctrl-P
	case 0x0e:
		return keyEvent{k: keyDown}, 1 // Ctrl-N
	}
	if b[0] < 0x20 {
		return keyEvent{}, 1
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError {
		if !utf8.FullRune(b) {
			return keyEvent{}, 0
		}
		return keyEvent{}, n
	}
	return keyEvent{k: keyRune, r: r}, n
}

// ----- layout -----

// visibleWindow returns the first index of the h items to show so that
// cur is visible, roughly centred.
func visibleWindow(cur, n, h int) int {
	if n <= h || h <= 0 {
		return 0
	}
	start := cur - h/2
	if start > n-h {
		start = n - h
	}
	if start < 0 {
		start = 0
	}
	return start
}

// truncate cuts s to width runes, ending with mark when it had to cut.
func truncate(s string, width int, mark string) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= width {
		return s
	}
	r, m := []rune(s), []rune(mark)
	if width <= len(m) {
		return string(r[:width])
	}
	return string(r[:width-len(m)]) + mark
}

// utf8Terminal guesses from the locale whether the terminal shows UTF-8.
func utf8Terminal() bool {
	for _, v := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if s := os.Getenv(v); s != "" {
			s = strings.ToLower(s)
			return strings.Contains(s, "utf-8") || strings.Contains(s, "utf8")
		}
	}
	return false
}

// item is one list line; entry is "" for a folder line in tree view.
type item struct{ text, entry string }

// buildItems lays out matches as a flat list or as a tree (without the
// root line; the header already names the store).
func buildItems(matches []string, tree bool) []item {
	if !tree {
		out := make([]item, len(matches))
		for i, m := range matches {
			out[i] = item{m, m}
		}
		return out
	}
	lines, entries := renderTree(matches, "", false)
	out := make([]item, 0, len(lines)-1)
	for i := 1; i < len(lines); i++ {
		out = append(out, item{lines[i], entries[i]})
	}
	return out
}

// ----- the picker -----

type picker struct {
	names   []string
	label   string
	filter  []rune
	matches []string
	tree    bool
	items   []item
	cur     int
	rows    int
	cols    int
	drawn   int // lines currently on screen
	pointer string
	ellip   string
	mark    string // fake cursor after the filter
}

func (p *picker) resize(fd int) {
	p.cols, p.rows = 80, 24
	if c, r, err := term.GetSize(fd); err == nil && c > 0 && r > 0 {
		p.cols, p.rows = c, r
	}
}

func (p *picker) refilter() {
	p.matches = matchEntries(p.names, string(p.filter))
	p.items = buildItems(p.matches, p.tree)
	p.cur = p.firstSelectable(0, 1)
}

// firstSelectable returns the first entry index from i going in dir, or -1.
func (p *picker) firstSelectable(i, dir int) int {
	for ; i >= 0 && i < len(p.items); i += dir {
		if p.items[i].entry != "" {
			return i
		}
	}
	return -1
}

// move steps the cursor n entries in direction dir, skipping folder lines.
func (p *picker) move(n, dir int) {
	for ; n > 0; n-- {
		j := p.firstSelectable(p.cur+dir, dir)
		if j < 0 {
			return
		}
		p.cur = j
	}
}

func (p *picker) height() int {
	h := p.rows - 3
	if h < 3 {
		h = 3
	}
	if len(p.items) < h {
		h = len(p.items)
	}
	if h < 1 {
		h = 1
	}
	return h
}

// header shows the store, the entry count and the filter; on a narrow
// terminal the store label gives way first, the filter stays visible.
func (p *picker) header(w int) string {
	filter := "> " + string(p.filter) + p.mark
	tail := fmt.Sprintf("   %d entries   %s", len(p.names), filter)
	if avail := w - utf8.RuneCountInString(tail); avail >= 4 {
		return truncate(p.label, avail, p.ellip) + tail
	}
	if r := []rune(filter); len(r) > w && w > 0 {
		return string(r[len(r)-w:]) // the end of a long filter is what is being typed
	}
	return filter
}

func (p *picker) lines() []string {
	w := p.cols - 1
	out := []string{p.header(w)}
	if len(p.items) == 0 {
		out = append(out, "  (no match)")
	} else {
		h := p.height()
		start := visibleWindow(p.cur, len(p.items), h)
		for i := start; i < start+h && i < len(p.items); i++ {
			prefix := "  "
			if i == p.cur {
				prefix = p.pointer
			}
			out = append(out, prefix+truncate(p.items[i].text, w-2, p.ellip))
		}
	}
	view := "tree"
	if p.tree {
		view = "list"
	}
	status := fmt.Sprintf("%d matches · ↑/↓ move · Enter select · Esc cancel · Tab complete · Ctrl-R %s", len(p.matches), view)
	if p.pointer == "> " {
		status = fmt.Sprintf("%d matches | up/down move | Enter select | Esc cancel | Tab complete | Ctrl-R %s", len(p.matches), view)
	}
	return append(out, "\033[2m"+truncate(status, w, p.ellip)+"\033[0m")
}

// draw repaints the picker in place: back up to its first line, clear to
// the end of the screen, print. Raw mode has no output processing, so
// lines end in \r\n and the last one has no newline (no scrolling).
func (p *picker) draw(t *os.File) {
	var b strings.Builder
	if p.drawn > 1 {
		fmt.Fprintf(&b, "\033[%dA", p.drawn-1)
	}
	b.WriteString("\r\033[J")
	ls := p.lines()
	for i, l := range ls {
		b.WriteString(l)
		if i < len(ls)-1 {
			b.WriteString("\r\n")
		}
	}
	p.drawn = len(ls)
	t.WriteString(b.String())
}

func (p *picker) clear(t *os.File) {
	if p.drawn > 1 {
		fmt.Fprintf(t, "\033[%dA", p.drawn-1)
	}
	t.WriteString("\r\033[J")
	p.drawn = 0
}

// handle applies one key. done is true when a choice was made (name) or
// the picker was cancelled (err).
func (p *picker) handle(ev keyEvent) (done bool, name string, err error) {
	switch ev.k {
	case keyRune:
		p.filter = append(p.filter, ev.r)
		p.refilter()
	case keyBackspace:
		if len(p.filter) > 0 {
			p.filter = p.filter[:len(p.filter)-1]
			p.refilter()
		}
	case keyCtrlU:
		if len(p.filter) > 0 {
			p.filter = p.filter[:0]
			p.refilter()
		}
	case keyTab:
		lcp := longestCommonPrefix(p.matches)
		f := string(p.filter)
		if len(lcp) > len(f) && strings.HasPrefix(strings.ToLower(lcp), strings.ToLower(f)) {
			p.filter = []rune(lcp)
			p.refilter()
		}
	case keyCtrlR:
		p.tree = !p.tree
		p.items = buildItems(p.matches, p.tree)
		p.cur = p.firstSelectable(0, 1)
	case keyUp:
		p.move(1, -1)
	case keyDown:
		p.move(1, 1)
	case keyPgUp:
		p.move(p.height(), -1)
	case keyPgDn:
		p.move(p.height(), 1)
	case keyHome:
		p.cur = p.firstSelectable(0, 1)
	case keyEnd:
		p.cur = p.firstSelectable(len(p.items)-1, -1)
	case keyEnter:
		if p.cur >= 0 && p.cur < len(p.items) && p.items[p.cur].entry != "" {
			return true, p.items[p.cur].entry, nil
		}
	case keyEsc, keyCancel:
		return true, "", errors.New("cancelled")
	}
	return false, "", nil
}

// waitInput waits up to ms milliseconds for input on fd, independently of
// whether Go's runtime manages the fd. It uses select(2), not poll(2): on
// macOS "the poll() system call currently does not support devices"
// (poll(2), BUGS) and reports POLLNVAL for /dev/tty, which froze the picker.
// EINTR is reported as "nothing yet" so the caller can act on a resize.
func waitInput(fd, ms int) (bool, error) {
	if fd >= 1024 { // does not fit an FdSet; never the case for the tty, which is opened early
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return n > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0, nil
	}
	var set unix.FdSet
	set.Set(fd)
	tv := unix.NsecToTimeval(int64(ms) * int64(time.Millisecond))
	n, err := unix.Select(fd+1, &set, nil, nil, &tv)
	if err == unix.EINTR {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return n > 0 && set.IsSet(fd), nil
}

// pickEntry runs the picker on terminal t and returns the chosen entry.
func pickEntry(t *os.File, names []string, initial string) (string, error) {
	fd := int(t.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			t.WriteString("\033[?25h") // cursor back
			term.Restore(fd, old)
		})
	}
	defer restore()

	// Ctrl-C arrives as a byte in raw mode, but a signal from outside would
	// leave the terminal raw: restore it, then let the signal do its work.
	var resized atomic.Bool
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	defer func() { signal.Stop(sig); close(sig) }()
	go func() {
		for s := range sig {
			if s == syscall.SIGWINCH {
				resized.Store(true)
				continue
			}
			restore()
			signal.Reset(s)
			syscall.Kill(syscall.Getpid(), s.(syscall.Signal))
			return
		}
	}()

	p := &picker{names: names, label: storeLabel(), filter: []rune(initial),
		tree: os.Getenv("YKS_PICKER") == "tree", pointer: "> ", ellip: "...", mark: "_"}
	if utf8Terminal() {
		p.pointer, p.ellip, p.mark = "▸ ", "…", "▌"
	}
	p.resize(fd)
	p.refilter()
	t.WriteString("\033[?25l") // hide the cursor; the header shows a mark instead

	var buf []byte
	tmp := make([]byte, 64)
	dirty, first := true, true
	for {
		if resized.Swap(false) {
			p.resize(fd)
			dirty = true
		}
		if dirty {
			p.draw(t)
			dirty = false
		}
		ready, err := waitInput(fd, 250)
		if err != nil {
			p.clear(t)
			if first { // this terminal device cannot be waited on: use the numbered tree
				restore()
				return pickTree(filterEntries(names, initial), "")
			}
			return "", err
		}
		first = false
		if !ready {
			continue
		}
		n, err := t.Read(tmp)
		if err != nil {
			p.clear(t)
			return "", err
		}
		buf = append(buf, tmp[:n]...)
		for len(buf) > 0 {
			ev, used := decodeKey(buf)
			if used == 0 { // incomplete: more may follow, or it is a lone ESC
				if more, _ := waitInput(fd, 50); more {
					break
				}
				if buf[0] == 0x1b {
					ev, used = keyEvent{k: keyEsc}, 1
				} else {
					ev, used = keyEvent{}, len(buf)
				}
			}
			buf = buf[used:]
			done, name, err := p.handle(ev)
			dirty = true
			if !done {
				continue
			}
			p.clear(t)
			if err != nil {
				return "", err
			}
			restore()
			fmt.Fprintf(t, "selected: %s\n", name)
			return name, nil
		}
	}
}
