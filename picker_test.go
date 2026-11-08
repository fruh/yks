//go:build linux || darwin

package main

import (
	"os"
	"reflect"
	"testing"
)

// A pipe stands in for the tty: select(2) handles both on Linux and macOS,
// so CI on macOS exercises the path that poll(2) broke.
func TestWaitInput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fd := int(r.Fd())
	if ok, err := waitInput(fd, 20); err != nil || ok {
		t.Fatalf("empty pipe: ready=%v err=%v", ok, err)
	}
	if _, err := w.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if ok, err := waitInput(fd, 2000); err != nil || !ok {
		t.Fatalf("after a write: ready=%v err=%v", ok, err)
	}
	if _, err := r.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if ok, err := waitInput(fd, 2000); err != nil || !ok {
		t.Fatalf("closed writer (EOF) must be readable: ready=%v err=%v", ok, err)
	}
}

func TestMatchEntries(t *testing.T) {
	names := []string{"docs/passport", "legacy/digit-pin", "mail/work", "personal/github/p",
		"personal/github/work", "work/GitLab", "work/github-actions", "work"}

	got := matchEntries(names, "")
	if !reflect.DeepEqual(got, names) {
		t.Fatalf("empty filter must keep everything: %v", got)
	}

	// substring, case-insensitive, sorted order kept within a group
	got = matchEntries(names, "git")
	want := []string{"work/GitLab", "work/github-actions", "legacy/digit-pin", "personal/github/p", "personal/github/work"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("git: got %v", got)
	}

	// exact name first, then base-name prefix, then the rest
	got = matchEntries(names, "work")
	want = []string{"work", "mail/work", "personal/github/work", "work/GitLab", "work/github-actions"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("work: got %v", got)
	}

	// several words must all match
	got = matchEntries(names, "git work")
	want = []string{"personal/github/work", "work/GitLab", "work/github-actions"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("git work: got %v", got)
	}

	if got = matchEntries(names, "nothing"); len(got) != 0 {
		t.Fatalf("no match expected: %v", got)
	}
}

func TestLongestCommonPrefix(t *testing.T) {
	if p := longestCommonPrefix([]string{"personal/github/p", "personal/github/work"}); p != "personal/github/" {
		t.Fatalf("got %q", p)
	}
	if p := longestCommonPrefix([]string{"a", "b"}); p != "" {
		t.Fatalf("got %q", p)
	}
	if p := longestCommonPrefix([]string{"only"}); p != "only" {
		t.Fatalf("got %q", p)
	}
	if p := longestCommonPrefix(nil); p != "" {
		t.Fatalf("got %q", p)
	}
	if p := longestCommonPrefix([]string{"héllo", "hélp"}); p != "hél" {
		t.Fatalf("runes: got %q", p)
	}
}

func TestDecodeKey(t *testing.T) {
	cases := []struct {
		in   string
		k    key
		r    rune
		used int
	}{
		{"a", keyRune, 'a', 1},
		{"é", keyRune, 'é', 2},
		{"\r", keyEnter, 0, 1},
		{"\n", keyEnter, 0, 1},
		{"\x7f", keyBackspace, 0, 1},
		{"\t", keyTab, 0, 1},
		{"\x03", keyCancel, 0, 1},
		{"\x04", keyCancel, 0, 1},
		{"\x15", keyCtrlU, 0, 1},
		{"\x12", keyCtrlR, 0, 1},
		{"\x10", keyUp, 0, 1},
		{"\x0e", keyDown, 0, 1},
		{"\x1b[A", keyUp, 0, 3},
		{"\x1b[B", keyDown, 0, 3},
		{"\x1bOA", keyUp, 0, 3},
		{"\x1b[H", keyHome, 0, 3},
		{"\x1b[F", keyEnd, 0, 3},
		{"\x1b[1~", keyHome, 0, 4},
		{"\x1b[4~", keyEnd, 0, 4},
		{"\x1b[5~", keyPgUp, 0, 4},
		{"\x1b[6~", keyPgDn, 0, 4},
		{"\x1b[C", keyNone, 0, 3},  // right arrow: ignored but consumed
		{"\x1b[3~", keyNone, 0, 4}, // delete: ignored but consumed
		{"\x1bx", keyEsc, 0, 1},    // Alt-x: ESC, then x on the next round
		{"\x01", keyNone, 0, 1},    // other control key: ignored
		{"\x1b", keyNone, 0, 0},    // lone ESC so far: incomplete
		{"\x1b[", keyNone, 0, 0},   // incomplete CSI
		{"\x1b[5", keyNone, 0, 0},  // incomplete CSI with parameter
		{"\xc3", keyNone, 0, 0},    // incomplete UTF-8
	}
	for _, c := range cases {
		ev, used := decodeKey([]byte(c.in))
		if used != c.used || (used > 0 && (ev.k != c.k || ev.r != c.r)) {
			t.Errorf("%q: got k=%d r=%q used=%d, want k=%d r=%q used=%d", c.in, ev.k, ev.r, used, c.k, c.r, c.used)
		}
	}
	// several keys in one read: decode the first only
	if ev, used := decodeKey([]byte("ab")); ev.r != 'a' || used != 1 {
		t.Fatalf("got %q used %d", ev.r, used)
	}
}

func TestVisibleWindow(t *testing.T) {
	cases := []struct{ cur, n, h, want int }{
		{0, 5, 10, 0}, // everything fits
		{0, 100, 10, 0},
		{3, 100, 10, 0},
		{50, 100, 10, 45}, // centred
		{99, 100, 10, 90}, // clamped to the end
		{95, 100, 10, 90},
		{5, 100, 0, 0},
	}
	for _, c := range cases {
		if got := visibleWindow(c.cur, c.n, c.h); got != c.want {
			t.Errorf("visibleWindow(%d,%d,%d) = %d, want %d", c.cur, c.n, c.h, got, c.want)
		}
	}
	for cur := 0; cur < 100; cur++ { // the cursor is always inside the window
		s := visibleWindow(cur, 100, 7)
		if cur < s || cur >= s+7 {
			t.Fatalf("cur %d outside window [%d,%d)", cur, s, s+7)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10, "…"); got != "short" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("personal/github/work", 10, "…"); got != "personal/…" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("personal/github/work", 10, "..."); got != "persona..." {
		t.Fatalf("got %q", got)
	}
	if got := truncate("abc", 0, "…"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := truncate("abcdef", 1, "..."); got != "a" {
		t.Fatalf("mark wider than width: got %q", got)
	}
}

func TestHeaderKeepsFilterVisible(t *testing.T) {
	p := &picker{names: make([]string, 484), label: "/a/very/long/path/to/the/store", filter: []rune("gith"), mark: "_", ellip: "..."}
	if h := p.header(79); h != "/a/very/long/path/to/the/store   484 entries   > gith_" {
		t.Fatalf("wide: %q", h)
	}
	if h := p.header(40); h != "/a/very/long/...   484 entries   > gith_" || len([]rune(h)) != 40 {
		t.Fatalf("narrow: %q (%d)", h, len([]rune(h)))
	}
	if h := p.header(12); h != "> gith_" {
		t.Fatalf("tiny: %q", h)
	}
	p.filter = []rune("a/very/long/filter/text")
	if h := p.header(10); h != "lter/text_" {
		t.Fatalf("filter wider than the terminal must show its end: %q", h)
	}
}

func TestBuildItems(t *testing.T) {
	m := []string{"github/personal", "github/work", "test"}
	flat := buildItems(m, false)
	if len(flat) != 3 || flat[1].text != "github/work" || flat[1].entry != "github/work" {
		t.Fatalf("flat: %+v", flat)
	}
	tree := buildItems(m, true)
	// github/, personal, work, test: 4 lines, the folder is not selectable
	if len(tree) != 4 || tree[0].entry != "" || tree[1].entry != "github/personal" ||
		tree[2].entry != "github/work" || tree[3].entry != "test" {
		t.Fatalf("tree: %+v", tree)
	}
}

func TestPickerMovesOverFoldersOnly(t *testing.T) {
	p := &picker{names: []string{"github/personal", "github/work", "test"}, tree: true, rows: 24, cols: 80}
	p.refilter()
	if p.cur != 1 {
		t.Fatalf("first selectable in tree view should be 1 (after the folder), got %d", p.cur)
	}
	p.move(1, 1)
	p.move(1, 1)
	if p.items[p.cur].entry != "test" {
		t.Fatalf("after two downs: %q", p.items[p.cur].entry)
	}
	p.move(5, 1) // cannot go past the end
	if p.items[p.cur].entry != "test" {
		t.Fatalf("overshoot: %q", p.items[p.cur].entry)
	}
	p.handle(keyEvent{k: keyHome})
	if p.cur != 1 {
		t.Fatalf("Home: %d", p.cur)
	}
	done, name, err := p.handle(keyEvent{k: keyEnter})
	if !done || err != nil || name != "github/personal" {
		t.Fatalf("Enter: %v %q %v", done, name, err)
	}
	if done, _, err := p.handle(keyEvent{k: keyEsc}); !done || err == nil {
		t.Fatal("Esc must cancel")
	}
}

func TestPickerTabCompletes(t *testing.T) {
	p := &picker{names: []string{"personal/github/p", "personal/github/work", "work/x"}, rows: 24, cols: 80}
	p.refilter()
	p.handle(keyEvent{k: keyRune, r: 'p'})
	p.handle(keyEvent{k: keyRune, r: 'e'})
	p.handle(keyEvent{k: keyTab})
	if string(p.filter) != "personal/github/" {
		t.Fatalf("after Tab: %q", string(p.filter))
	}
	p.handle(keyEvent{k: keyCtrlU})
	if len(p.filter) != 0 || len(p.matches) != 3 {
		t.Fatalf("Ctrl-U: %q %d", string(p.filter), len(p.matches))
	}
	p.handle(keyEvent{k: keyRune, r: 'z'})
	if len(p.items) != 0 || p.cur != -1 {
		t.Fatalf("no match: items=%d cur=%d", len(p.items), p.cur)
	}
	if done, _, _ := p.handle(keyEvent{k: keyEnter}); done {
		t.Fatal("Enter with no match must do nothing")
	}
	if ls := p.lines(); len(ls) != 3 || ls[1] != "  (no match)" {
		t.Fatalf("lines with no match: %q", ls)
	}
}
