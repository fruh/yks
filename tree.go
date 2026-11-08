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
//   - no filter:         pick from all entries
//   - exact entry name:  that entry, even if it also matches others
//   - one match:         that entry (announced on the terminal)
//   - several matches:   pick, with the filter pre-filled
func resolveEntry(filter string) (string, error) {
	names, err := listEntries()
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("store is empty")
	}
	if filter == "" {
		return chooseEntry(names, "", "")
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
	return chooseEntry(names, filter, fmt.Sprintf("%d entries match %q:", len(m), filter))
}

// pickTree shows names (all entries when nil) as a numbered tree on the
// terminal and returns the chosen one. It is the fallback for chooseEntry
// when there is no usable terminal or YKS_PICKER=plain is set.
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
	lines, entries := renderTree(names, storeLabel(), true)
	var order []string // index-1 -> entry, in display order
	for _, e := range entries {
		if e != "" {
			order = append(order, e)
		}
	}
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

// renderTree draws names as a tree. entries is aligned with lines and holds
// the entry name of each line, "" for the root and for folders. With
// numbered, each entry gets its index in brackets after the name, counting
// in display order. An entry that is also a folder ("work" and "work/vpn")
// is shown once, with its index and its children.
//
//	~/.ykstore
//	├── github/
//	│   ├── personal [1]
//	│   └── work [2]
//	└── test [3]
func renderTree(names []string, rootLabel string, numbered bool) (lines, entries []string) {
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
	lines, entries = append(lines, rootLabel), append(entries, "")
	count := 0

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
				count++
				label += fmt.Sprintf(" [%d]", count)
			}
			lines, entries = append(lines, prefix+branch+label), append(entries, c.entry)
			walk(c, prefix+indent)
		}
	}
	walk(root, "")
	return lines, entries
}
