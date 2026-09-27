//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// cmdRekey re-encrypts every entry with the current .config settings, or with
// new ones given as flags, under a fresh store salt:
//
//  1. copy everything that is not an entry (.git, other files) into a new
//     sibling directory
//  2. decrypt each entry, re-encrypt it into the new directory, read it back
//     and verify it decrypts to the same plaintext
//  3. only if every entry succeeded: rename the old store to <store>.bak-<time>
//     and the new directory into its place
//
// Any failure before step 3 leaves the store untouched.
func cmdRekey(args []string, globalSlot int) error {
	fl := flag.NewFlagSet("rekey", flag.ExitOnError)
	fl.Usage = usage
	newPw := fl.Bool("p", false, "")
	slot := fl.Int("s", globalSlot, "")
	dev := fl.String("new-device", "", "")
	mib := fl.Int("m", 0, "")
	iters := fl.Int("t", 0, "")
	_ = fl.Parse(args)
	if fl.NArg() != 0 {
		usage()
	}

	c, err := loadConfig()
	if err != nil {
		return err
	}
	if *dev != "" && !validSerial(*dev) {
		return fmt.Errorf("invalid YubiKey serial %q", *dev)
	}
	if _, err := device(); err != nil { // the key to decrypt with, asked before passwords
		return err
	}
	nc := *c
	if *dev != "" && c.Device != "" {
		nc.Device = *dev // the configured default moves to the new key
	}
	if *slot != 0 {
		if *slot != 1 && *slot != 2 {
			return errors.New("slot must be 1 or 2")
		}
		nc.Slot = *slot
	}
	m, t := int(c.KDF.M/1024), int(c.KDF.T)
	if *mib != 0 {
		m = *mib
	}
	if *iters != 0 {
		t = *iters
	}
	if nc.KDF, err = argonFromFlags(m, t); err != nil { // always a fresh salt
		return err
	}

	names, err := listEntries()
	if err != nil {
		return err
	}
	root := filepath.Clean(storeDir())
	fmt.Fprintf(os.Stderr, "rekey %d entries: slot %d -> %d, Argon2id %d MiB/t=%d -> %d MiB/t=%d, new salt",
		len(names), c.Slot, nc.Slot, c.KDF.M/1024, c.KDF.T, m, t)
	if *newPw {
		fmt.Fprint(os.Stderr, ", new master password")
	}
	if *dev != "" {
		fmt.Fprintf(os.Stderr, ", encrypting with YubiKey %s", *dev)
	}
	fmt.Fprintln(os.Stderr)

	// The password is always typed here: the cache holds only derived keys,
	// and a new salt needs the password itself.
	pw, err := readSecret("Current master password: ")
	if err != nil {
		return err
	}
	defer clear(pw)
	npw := pw
	if *newPw {
		a, err := readSecret("New master password: ")
		if err != nil {
			return err
		}
		defer clear(a)
		b, err := readSecret("Retype new master password: ")
		if err != nil {
			return err
		}
		same := bytes.Equal(a, b)
		clear(b)
		if !same {
			return errors.New("new passwords do not match")
		}
		npw = a
	}

	newPK := argon2.IDKey(npw, nc.KDF.Salt, nc.KDF.T, nc.KDF.M, nc.KDF.P, 32)
	defer clear(newPK)
	old := &oldKeys{pws: [][]byte{append([]byte{}, pw...)}, pks: map[string][]byte{}}
	defer old.wipe()

	tmp, err := os.MkdirTemp(filepath.Dir(root), "."+filepath.Base(root)+".rekey-")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(tmp)
		}
	}()
	if err := copyNonEntries(root, tmp); err != nil {
		return fmt.Errorf("copying store: %w", err)
	}

	for i, n := range names {
		fmt.Fprintf(os.Stderr, "[%d/%d] %s\n", i+1, len(names), n)
		if err := rekeyEntry(n, tmp, old, newPK, nc, *dev); err != nil {
			return fmt.Errorf("%s: %w (nothing was changed)", n, err)
		}
	}
	if err := writeAtomic(filepath.Join(tmp, ".config"), []byte(nc.String())); err != nil {
		return err
	}

	backup := root + ".bak-" + time.Now().Format("20060102-150405")
	if err := os.Rename(root, backup); err != nil {
		return fmt.Errorf("cannot move old store aside (is %s a mount point?): %w", root, err)
	}
	if err := os.Rename(tmp, root); err != nil {
		if rerr := os.Rename(backup, root); rerr != nil {
			return fmt.Errorf("swap failed: new store is at %s, old store at %s; move one back to %s by hand: %w",
				tmp, backup, root, err)
		}
		return fmt.Errorf("swap failed, old store restored: %w", err)
	}
	done = true

	gitAuto(fmt.Sprintf("yks: rekey %d entries", len(names)), ".")
	agentStop() // drop keys derived from the old salt/password
	cachePut(nc.KDF.cacheID(), newPK, cacheTTL())
	fmt.Fprintf(os.Stderr, "rekeyed %d entries.\n", len(names))
	if len(old.pws) > 1 {
		fmt.Fprintf(os.Stderr, "entries used %d different master passwords; all now use the same one.\n", len(old.pws))
	}
	fmt.Fprintf(os.Stderr, "old store kept at %s\n", backup)
	fmt.Fprintf(os.Stderr, "check a few entries, then delete it: rm -rf %q\n", backup)
	return nil
}

// oldKeys holds every master password that opened some entry during rekey,
// with Argon2 outputs cached per (password, settings) pair.
type oldKeys struct {
	pws [][]byte
	pks map[string][]byte
}

func (o *oldKeys) pk(i int, k kdf) []byte {
	id := fmt.Sprintf("%s#%d", k.cacheID(), i)
	if pk, ok := o.pks[id]; ok {
		return pk
	}
	pk := argon2.IDKey(o.pws[i], k.Salt, k.T, k.M, k.P, 32)
	o.pks[id] = pk
	return pk
}

func (o *oldKeys) wipe() {
	for _, p := range o.pws {
		clear(p)
	}
	for _, k := range o.pks {
		clear(k)
	}
}

// rekeyEntry re-encrypts one entry. It tries every password that has opened
// an entry so far (one YubiKey operation each), then asks for this entry's
// password up to maxTries times and remembers it for later entries.
func rekeyEntry(name, tmp string, old *oldKeys, newPK []byte, nc config, dev string) error {
	_, path, err := entry(name)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	slot, k, seed, nonce, err := parseHeader(b)
	if err != nil {
		return err
	}
	open := func(pk []byte) ([]byte, error) {
		aead, err := newAEAD(pk, seed, slot, "")
		if err != nil {
			return nil, err
		}
		pt, err := aead.Open(nil, nonce, b[hdrLen:], aad(b[:hdrLen], name))
		if err != nil {
			return nil, nil
		}
		return pt, nil
	}
	var pt []byte
	for i := range old.pws {
		if pt, err = open(old.pk(i, k)); err != nil {
			return err
		}
		if pt != nil {
			break
		}
	}
	for try := 1; pt == nil && try <= maxTries; try++ {
		if try == 1 {
			fmt.Fprintf(os.Stderr, "the known master password(s) do not open %s\n", name)
		} else {
			fmt.Fprintf(os.Stderr, "wrong master password (or YubiKey), try again (%d/%d)\n", try-1, maxTries)
		}
		pw, err := readSecret(fmt.Sprintf("Master password for %s: ", name))
		if err != nil {
			return err
		}
		old.pws = append(old.pws, pw)
		i := len(old.pws) - 1
		if pt, err = open(old.pk(i, k)); err != nil {
			return err
		}
		if pt == nil { // forget the wrong password again
			clear(pw)
			old.pws = old.pws[:i]
			id := fmt.Sprintf("%s#%d", k.cacheID(), i)
			clear(old.pks[id])
			delete(old.pks, id)
		}
	}
	if pt == nil {
		return errors.New("cannot decrypt: wrong master password or YubiKey")
	}
	defer clear(pt)

	out, naead, err := sealEntry(newPK, nc.KDF, nc.Slot, dev, name, pt)
	if err != nil {
		return err
	}
	dst := filepath.Join(tmp, filepath.FromSlash(name)+".yks")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(dst, out); err != nil {
		return err
	}

	// Verify what is on disk (no extra YubiKey touch: the AEAD is reused).
	back, err := os.ReadFile(dst)
	if err != nil {
		return err
	}
	_, _, _, bnonce, err := parseHeader(back)
	if err != nil {
		return err
	}
	pt2, err := naead.Open(nil, bnonce, back[hdrLen:], aad(back[:hdrLen], name))
	if err != nil || !bytes.Equal(pt, pt2) {
		return errors.New("verification of the re-encrypted file failed")
	}
	clear(pt2)
	return nil
}

// copyNonEntries copies everything except entries (*.yks) and the top-level
// .config into dst, so git history and other files survive the swap.
func copyNonEntries(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		inGit := rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator))
		if rel == ".config" || (!inGit && strings.HasSuffix(rel, ".yks") && !d.IsDir()) {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case info.Mode()&fs.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, target)
		case info.Mode().IsRegular():
			return copyFile(p, target, info.Mode().Perm())
		}
		return nil // sockets, devices etc. are skipped
	})
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
