//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// cmdSync synchronises the store with its git upstream:
//
//  1. commit pending changes to entries, .config and .gitignore (nothing
//     else, so a stray plaintext file is never committed)
//  2. fetch
//  3. fast-forward, or rebase local commits on top of the upstream
//  4. push
//
// Entries are encrypted, so git cannot merge two versions of the same
// entry. On a conflict the rebase is aborted, the store is left exactly as
// it was, and the conflicting entries are listed.
func cmdSync() error {
	root := storeDir()
	if _, err := exec.LookPath("git"); err != nil {
		return errors.New("git is not installed")
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return fmt.Errorf("%s is not a git repository (see 'History with git' in the README)", root)
	}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return strings.TrimSpace(out.String()), fmt.Errorf("git %s failed: %s", args[0], strings.TrimSpace(errb.String()))
		}
		return strings.TrimSpace(out.String()), nil
	}

	for _, f := range []string{"rebase-merge", "rebase-apply", "MERGE_HEAD"} {
		if _, err := os.Stat(filepath.Join(root, ".git", f)); err == nil {
			return fmt.Errorf("a git rebase or merge is in progress in %s: finish it or abort it first (git -C %q rebase --abort)", root, root)
		}
	}
	upstream, err := git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
	if err != nil {
		return fmt.Errorf("the current branch has no upstream; set one once with:\n  git -C %q remote add origin <url>   # if there is no remote yet\n  git -C %q push -u origin HEAD", root, root)
	}

	// 1. Commit pending yks changes only.
	paths, others, err := pendingChanges(root)
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		if _, err := git(append([]string{"add", "-A", "--"}, paths...)...); err != nil {
			return err
		}
		msg := fmt.Sprintf("yks: sync %d local change(s)", len(paths))
		if _, err := git(append([]string{"commit", "-q", "-m", msg, "--"}, paths...)...); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "committed %d local change(s)\n", len(paths))
	}
	if len(others) > 0 {
		fmt.Fprintf(os.Stderr, "warning: not synced (not entries): %s\n", strings.Join(others, ", "))
	}

	configBefore, _ := os.ReadFile(configPath())

	// 2. Fetch.
	fmt.Fprintf(os.Stderr, "fetching %s ...\n", upstream)
	if _, err := git("fetch", "--quiet"); err != nil {
		return err
	}
	ahead, behind, err := aheadBehind(git)
	if err != nil {
		return err
	}

	// 3. Integrate remote changes.
	pulled := behind
	if behind > 0 {
		if ahead == 0 {
			if _, err := git("merge", "--ff-only", "--quiet", "@{u}"); err != nil {
				return err
			}
		} else if _, err := git("-c", "rebase.autoStash=false", "rebase", "--quiet", "@{u}"); err != nil {
			conflicts, _ := git("diff", "--name-only", "--diff-filter=U")
			_, _ = git("rebase", "--abort")
			return syncConflict(root, upstream, conflicts, err)
		}
	}

	// 4. Push.
	if ahead, _, err = aheadBehind(git); err != nil {
		return err
	}
	if ahead > 0 {
		fmt.Fprintf(os.Stderr, "pushing to %s ...\n", upstream)
		if _, err := git("push", "--quiet"); err != nil {
			return err
		}
	}

	switch {
	case pulled == 0 && ahead == 0:
		fmt.Fprintf(os.Stderr, "up to date with %s\n", upstream)
	default:
		fmt.Fprintf(os.Stderr, "synced with %s: pulled %d, pushed %d commit(s)\n", upstream, pulled, ahead)
	}
	if configAfter, _ := os.ReadFile(configPath()); !bytes.Equal(configBefore, configAfter) {
		fmt.Fprintln(os.Stderr, "note: .config changed (new settings, or a rekey on another machine): run 'yks check'")
	}
	return nil
}

// pendingChanges lists changed or untracked paths that belong to yks
// (non-hidden *.yks entries, .config, .gitignore) and, separately, anything
// else that git sees as changed.
func pendingChanges(root string) (paths, others []string, err error) {
	out, err := exec.Command("git", "-C", root, "status", "--porcelain", "-z", "--untracked-files=all").Output()
	if err != nil {
		return nil, nil, fmt.Errorf("git status failed: %w", err)
	}
	fields := strings.Split(string(out), "\x00")
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if len(f) < 4 {
			continue
		}
		xy, p := f[:2], f[3:]
		if xy[0] == 'R' || xy[0] == 'C' { // rename/copy: next field is the old path
			if i+1 < len(fields) {
				old := fields[i+1]
				i++
				if isStorePath(old) {
					paths = append(paths, old)
				}
			}
		}
		if isStorePath(p) {
			paths = append(paths, p)
		} else {
			others = append(others, p)
		}
	}
	return paths, others, nil
}

// isStorePath: an entry (*.yks with no hidden path part), .config or .gitignore.
func isStorePath(p string) bool {
	p = filepath.ToSlash(p)
	if p == ".config" || p == ".gitignore" {
		return true
	}
	return strings.HasSuffix(p, ".yks") && !hiddenPath(p)
}

func aheadBehind(git func(...string) (string, error)) (ahead, behind int, err error) {
	out, err := git("rev-list", "--left-right", "--count", "HEAD...@{u}")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("unexpected git rev-list output %q", out)
	}
	ahead, _ = strconv.Atoi(f[0])
	behind, _ = strconv.Atoi(f[1])
	return ahead, behind, nil
}

func syncConflict(root, upstream, conflicts string, cause error) error {
	if conflicts == "" {
		return fmt.Errorf("rebase onto %s failed and was aborted, nothing was changed: %w", upstream, cause)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sync stopped: these files were changed both here and on %s:\n", upstream)
	rekey := false
	for _, f := range strings.Split(conflicts, "\n") {
		fmt.Fprintf(&b, "  %s\n", f)
		rekey = rekey || f == ".config"
	}
	b.WriteString("Encrypted entries cannot be merged. The rebase was aborted; nothing was changed.\n")
	if rekey {
		b.WriteString(".config conflicts too: probably 'yks rekey' or a settings change ran on both machines.\nKeep one side for every file, then run 'yks rekey' again if needed.\n")
	}
	fmt.Fprintf(&b, `To resolve, keep one version of each file:
  cd %q && git pull --rebase
  git checkout --theirs <file>   # keep YOUR local version (in a rebase, "theirs" is yours)
  git checkout --ours <file>     # or keep the REMOTE version
  git add <file> && git rebase --continue
  yks sync
To keep both versions of an entry, first save yours under another name:
  yks d <entry> | yks e <entry>-local`, root)
	return errors.New(b.String())
}
