//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"
)

// filterEntries keeps the names that contain filter anywhere, ignoring case.
func filterEntries(names []string, filter string) []string {
	if filter == "" {
		return names
	}
	q := strings.ToLower(filter)
	var out []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), q) {
			out = append(out, n)
		}
	}
	return out
}

// resolveEntry turns the argument of d / c into one entry name:
//   - no filter:         pick from a tree of all entries
//   - exact entry name:  that entry, even if it also matches others
//   - one match:         that entry (announced on the terminal)
//   - several matches:   pick from a tree of the matches
func resolveEntry(filter string) (string, error) {
	names, err := listEntries()
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("store is empty")
	}
	if filter == "" {
		return pickTree(names, "")
	}
	if canon, _, err := entry(filter); err == nil {
		for _, n := range names {
			if n == canon {
				return n, nil
			}
		}
	}
	m := filterEntries(names, filter)
	switch len(m) {
	case 0:
		return "", fmt.Errorf("no entry matches %q (see: yks ls)", filter)
	case 1:
		announce(m[0])
		return m[0], nil
	}
	return pickTree(m, fmt.Sprintf("%d entries match %q:", len(m), filter))
}

// pickTree shows names (all entries when nil) as a numbered tree on the
// terminal and returns the chosen one.
func pickTree(names []string, header string) (string, error) {
	if names == nil {
		var err error
		if names, err = listEntries(); err != nil {
			return "", err
		}
		if len(names) == 0 {
			return "", errors.New("store is empty")
		}
	}
	lines, order := renderTree(names, storeLabel(), true)
	t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("cannot show the list (no terminal): give an exact entry name: %w", err)
	}
	defer t.Close()
	if header != "" {
		fmt.Fprintln(t, header)
	}
	for _, l := range lines {
		fmt.Fprintln(t, l)
	}
	i, err := askIndex(t, len(order), "Entry", false)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(t, "selected: %s\n", order[i])
	return order[i], nil
}

// announce shows which entry was chosen automatically. It writes to the
// terminal, so it is visible even when stdout and stderr are redirected.
func announce(name string) {
	if t, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		fmt.Fprintf(t, "selected: %s\n", name)
		t.Close()
		return
	}
	fmt.Fprintf(os.Stderr, "selected: %s\n", name)
}

// cmdList prints entries as a tree on a terminal, or one name per line when
// stdout is piped or redirected (for scripts).
func cmdList(filter string) error {
	names, err := listEntries()
	if err != nil {
		return err
	}
	names = filterEntries(names, filter)
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	}
	if len(names) == 0 {
		if filter != "" {
			return fmt.Errorf("no entry matches %q", filter)
		}
		fmt.Println("(store is empty)")
		return nil
	}
	label := storeLabel()
	if filter != "" {
		label += fmt.Sprintf("  (matching %q)", filter)
	}
	lines, _ := renderTree(names, label, false)
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

// storeLabel is the store path with the home directory shown as ~.
func storeLabel() string {
	d := storeDir()
	if h, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(h, d); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(filepath.Join("~", rel))
		}
	}
	return d
}

type treeNode struct {
	children map[string]*treeNode
	entry    string // full entry name if this node is an entry
}

// renderTree draws names as a tree. With numbered, each entry gets its index
// in brackets after the name, and order maps index-1 to the entry name, in
// the same order as displayed. An entry that is also a folder ("work" and
// "work/vpn") is shown once, with its index and its children.
//
//	~/.ykstore
//	├── github/
//	│   ├── personal [1]
//	│   └── work [2]
//	└── test [3]
func renderTree(names []string, rootLabel string, numbered bool) (lines, order []string) {
	root := &treeNode{children: map[string]*treeNode{}}
	for _, n := range names {
		cur := root
		for _, part := range strings.Split(n, "/") {
			c, ok := cur.children[part]
			if !ok {
				c = &treeNode{children: map[string]*treeNode{}}
				cur.children[part] = c
			}
			cur = c
		}
		cur.entry = n
	}
	lines = append(lines, rootLabel)

	var walk func(n *treeNode, prefix string)
	walk = func(n *treeNode, prefix string) {
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			c := n.children[k]
			branch, indent := "├── ", "│   "
			if i == len(keys)-1 {
				branch, indent = "└── ", "    "
			}
			label := k
			if len(c.children) > 0 {
				label += "/"
			}
			if c.entry != "" && numbered {
				order = append(order, c.entry)
				label += fmt.Sprintf(" [%d]", len(order))
			}
			lines = append(lines, prefix+branch+label)
			walk(c, prefix+indent)
		}
	}
	walk(root, "")
	return lines, order
}
