//go:build linux || darwin

// yks - minimal YubiKey HMAC-SHA1 challenge-response secret store.
//
// Key derivation per entry:
//   pk        = Argon2id(master_password, store_salt)          (cached by the in-memory agent)
//   challenge = HMAC-SHA256(pk, "yks-v1 challenge" || seed)     (seed: 32 random bytes per file)
//   resp      = YubiKey_HMAC_SHA1(slot, challenge)
//   key       = HKDF-SHA256(ikm = resp || pk, salt = seed, info = "yks-v1 aes-256-gcm")
//   file      = header || AES-256-GCM(key, nonce, plaintext, aad = header || 0x00 || name)
//
// Both factors are needed: the YubiKey response alone is not the key, and the
// password alone is useless without the YubiKey.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"
)

const (
	magic    = "YKS1"
	saltLen  = 16
	seedLen  = 32
	nonceLen = 12
	// magic(4) slot(1) argon_t(4) argon_m(4) argon_p(1) salt(16) seed(32) nonce(12)
	hdrLen  = 14 + saltLen + seedLen + nonceLen
	clipTTL = 45 * time.Second

	// Argon2id defaults for new stores. 256 MiB / t=3 / p=4 exceeds the OWASP
	// minimum and RFC 9106's memory-constrained profile (64 MiB, t=3, p=4).
	defaultArgonMiB = 256
	defaultArgonT   = 3
	argonP          = 4
)

type kdf struct {
	T, M uint32 // iterations, memory in KiB
	P    uint8  // parallelism
	Salt []byte
}

func (k kdf) bytes() []byte {
	b := binary.BigEndian.AppendUint32(nil, k.T)
	b = binary.BigEndian.AppendUint32(b, k.M)
	return append(append(b, k.P), k.Salt...)
}

// Bounds also protect against a malicious file demanding absurd Argon2 costs.
func (k kdf) valid() bool {
	return k.T >= 1 && k.T <= 20 && k.M >= 8*1024 && k.M <= 4*1024*1024 &&
		k.P >= 1 && k.P <= 16 && len(k.Salt) == saltLen
}

func (k kdf) cacheID() string {
	h := sha256.Sum256(k.bytes())
	return "yks:" + hex.EncodeToString(h[:12])
}

type config struct {
	Slot   int
	KDF    kdf
	Device string // optional default YubiKey serial
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: yks <command> [args] [-s 1|2] [-d SERIAL] [-f] [-a]
       (flags may go before or after the command; -- ends flags)
  init [-m MiB] [-t N]
                    create the store and choose a default slot
                    (Argon2id memory, default 256 MiB; iterations, default 3)
  e <name> [file]   encrypt file (or stdin, or prompt) into entry <name>
  d [name]          decrypt entry to stdout (no name: pick from a numbered list)
  c [name]          decrypt, copy first line to clipboard, cleared after 45s
                    (-a: copy the entire entry)
                    (no name: pick from a numbered list)
  rm [name]         remove entry after confirmation, -f skips it
                    (no name: pick from a numbered list)
  ls                list entries
  forget            stop the cache agent, wiping cached keys
  check             check dependencies, YubiKey, store and agent
  version           print version
  rekey [-p] [-s 1|2] [-new-device SERIAL] [-m MiB] [-t N]
                    re-encrypt every entry with the current (or new) settings:
                    -p new master password, -s new slot, -new-device YubiKey
                    to encrypt with (-d picks the one to decrypt with),
                    -m/-t new Argon2id settings
flags: -s slot for new entries (default from config),
       -d, --device SERIAL  YubiKey to use (see: ykman list --serials),
       -f overwrite on 'e', no confirmation on 'rm',
       -a copy the entire entry with 'c'
env:   YKS_DIR (default ~/.ykstore), YKS_CACHE_TTL seconds (default 300, 0 = off),
       YKS_DEVICE default YubiKey serial (also: device= in .config),
       YKS_GIT=1 commit changes automatically if the store is a git repository
`)
	os.Exit(2)
}

func die(err error) { fmt.Fprintln(os.Stderr, "yks:", err); os.Exit(1) }

func main() {
	harden()
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "__clipclear":
			clipClearChild()
			return
		case "__agent":
			runAgent()
			return
		}
	}
	fl := flag.NewFlagSet("yks", flag.ExitOnError)
	fl.Usage = usage
	slot := fl.Int("s", 0, "")
	force := fl.Bool("f", false, "")
	all := fl.Bool("a", false, "")
	fl.StringVar(&flagDevice, "d", "", "")
	fl.StringVar(&flagDevice, "device", "", "")
	flags, a, literal, err := splitArgs(os.Args[1:])
	if err != nil {
		die(err)
	}
	_ = fl.Parse(flags)
	if len(a) == 0 {
		usage()
	}
	// init and rekey parse their own flags (-m, -t, -p, -d); every other
	// command takes only names, so a leftover "-x" is a typo, not an entry.
	if a[0] != "init" && a[0] != "rekey" {
		for _, x := range a[1:max(literal, 1)] {
			if strings.HasPrefix(x, "-") && x != "-" {
				die(fmt.Errorf("unknown flag %s (put -- before an entry name that starts with -)", x))
			}
		}
	}
	if *all && a[0] != "c" {
		die(errors.New("-a only applies to 'c'"))
	}
	if *slot != 0 && *slot != 1 && *slot != 2 {
		die(errors.New("slot must be 1 or 2"))
	}
	if flagDevice != "" && !validSerial(flagDevice) {
		die(fmt.Errorf("invalid YubiKey serial %q (see: ykman list --serials)", flagDevice))
	}
	switch a[0] {
	case "e", "d", "rekey":
		err = requireDeps(false)
	case "c":
		err = requireDeps(true)
	}
	if err != nil {
		die(err)
	}
	switch {
	case a[0] == "version" && len(a) == 1:
		fmt.Println("yks", versionString())
	case a[0] == "check" && len(a) == 1:
		err = cmdCheck()
	case a[0] == "init":
		err = cmdInit(a[1:], *slot)
	case a[0] == "rekey":
		err = cmdRekey(a[1:], *slot)
	case a[0] == "e" && (len(a) == 2 || len(a) == 3):
		in := ""
		if len(a) == 3 {
			in = a[2]
		}
		err = cmdEncrypt(a[1], in, *slot, *force)
	case (a[0] == "d" || a[0] == "c") && len(a) <= 2:
		name := ""
		if len(a) == 2 {
			name = a[1]
		} else if name, err = pickEntry(); err != nil {
			break
		}
		err = cmdDecrypt(name, a[0] == "c", *all)
	case a[0] == "rm" && len(a) <= 2:
		name := ""
		if len(a) == 2 {
			name = a[1]
		} else if name, err = pickEntry(); err != nil {
			break
		}
		err = cmdRemove(name, *force)
	case a[0] == "ls" && len(a) == 1:
		err = cmdList()
	case a[0] == "forget" && len(a) == 1:
		agentStop()
	default:
		usage()
	}
	if err != nil {
		die(err)
	}
}

// splitArgs pulls the global flags (-s N, -d SERIAL, -f, -a, -h) out of args wherever
// they appear, so both "yks -a c name" and "yks c name -a" work. Everything
// else keeps its order. "--" ends flag parsing; literal is the index in rest
// from which arguments were given after "--" (len(rest) if there was none).
func splitArgs(args []string) (flags, rest []string, literal int, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			literal = len(rest)
			return flags, append(rest, args[i+1:]...), literal, nil
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			rest = append(rest, arg)
			continue
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch name {
		case "f", "a", "h", "help":
			flags = append(flags, arg)
		case "s", "d", "device":
			flags = append(flags, arg)
			if !hasValue {
				if i+1 >= len(args) {
					return nil, nil, 0, fmt.Errorf("%s needs a value", arg)
				}
				i++
				flags = append(flags, args[i])
			}
		default: // unknown here; maybe a flag of init or rekey
			rest = append(rest, arg)
		}
	}
	return flags, rest, len(rest), nil
}

// ---------- store / config ----------

func storeDir() string {
	if d := os.Getenv("YKS_DIR"); d != "" {
		return d
	}
	h, err := os.UserHomeDir()
	if err != nil {
		die(err)
	}
	return filepath.Join(h, ".ykstore")
}

func configPath() string { return filepath.Join(storeDir(), ".config") }

func (c config) String() string {
	s := fmt.Sprintf("slot=%d\nargon_t=%d\nargon_m=%d\nargon_p=%d\nsalt=%x\n",
		c.Slot, c.KDF.T, c.KDF.M, c.KDF.P, c.KDF.Salt)
	if c.Device != "" {
		s += "device=" + c.Device + "\n"
	}
	return s
}

// argonFromFlags turns -m (MiB) / -t values into KDF settings with a fresh salt.
func argonFromFlags(mib, iters int) (kdf, error) {
	if mib < 8 || mib > 4096 || iters < 1 || iters > 20 {
		return kdf{}, errors.New("invalid Argon2id settings: -m must be 8..4096 (MiB), -t 1..20")
	}
	return kdf{T: uint32(iters), M: uint32(mib) * 1024, P: argonP, Salt: randBytes(saltLen)}, nil
}

func cmdInit(args []string, slot int) error {
	fl := flag.NewFlagSet("init", flag.ExitOnError)
	fl.Usage = usage
	mib := fl.Int("m", defaultArgonMiB, "")
	iters := fl.Int("t", defaultArgonT, "")
	_ = fl.Parse(args)
	if fl.NArg() != 0 {
		usage()
	}
	k, err := argonFromFlags(*mib, *iters)
	if err != nil {
		return err
	}
	if _, err := os.Stat(configPath()); err == nil {
		return errors.New("store already initialised: " + storeDir() + " (use 'yks rekey' to change settings)")
	}
	if err := os.MkdirAll(storeDir(), 0o700); err != nil {
		return err
	}
	for slot != 1 && slot != 2 {
		s, err := prompt("Default YubiKey slot [1/2]: ")
		if err != nil {
			return err
		}
		slot, _ = strconv.Atoi(strings.TrimSpace(s))
	}
	c := config{Slot: slot, KDF: k, Device: flagDevice}
	if c.Device == "" {
		if keys, err := listYubiKeys(); err == nil && len(keys) > 1 {
			if c.Device, err = pickYubiKey(keys, true); err != nil {
				return err
			}
		}
	}
	if err := writeAtomic(configPath(), []byte(c.String())); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "initialised %s (default slot %d, Argon2id %d MiB, t=%d)\n",
		storeDir(), slot, *mib, *iters)
	if c.Device != "" {
		fmt.Fprintf(os.Stderr, "default YubiKey: %s\n", c.Device)
	}
	return nil
}

func loadConfig() (*config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return nil, fmt.Errorf("no store config, run 'yks init' (%w)", err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	num := func(k string) uint32 { n, _ := strconv.ParseUint(m[k], 10, 32); return uint32(n) }
	c := &config{Slot: int(num("slot")), KDF: kdf{T: num("argon_t"), M: num("argon_m"), P: uint8(num("argon_p"))},
		Device: m["device"]}
	c.KDF.Salt, err = hex.DecodeString(m["salt"])
	if err != nil || !c.KDF.valid() || (c.Slot != 1 && c.Slot != 2) || (c.Device != "" && !validSerial(c.Device)) {
		return nil, errors.New("invalid config " + configPath())
	}
	return c, nil
}

// entry returns the canonical name (bound into the ciphertext) and file path.
func entry(name string) (string, string, error) {
	n := filepath.ToSlash(filepath.Clean(strings.TrimSuffix(name, ".yks")))
	if n == "" || filepath.IsAbs(n) || strings.HasPrefix(n, ".") {
		return "", "", fmt.Errorf("invalid entry name %q", name)
	}
	return n, filepath.Join(storeDir(), filepath.FromSlash(n)+".yks"), nil
}

func listEntries() ([]string, error) {
	root := storeDir()
	var names []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yks") {
			rel, _ := filepath.Rel(root, p)
			names = append(names, filepath.ToSlash(strings.TrimSuffix(rel, ".yks")))
		}
		return nil
	})
	return names, err // WalkDir visits in lexical order, so the list is sorted
}

func cmdList() error {
	names, err := listEntries()
	for _, n := range names {
		fmt.Println(n)
	}
	return err
}

// pickEntry asks which entry to use, from a numbered list.
func pickEntry() (string, error) {
	names, err := listEntries()
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("store is empty")
	}
	i, err := pickFrom("", names, "Entry", false)
	if err != nil {
		return "", err
	}
	return names[i], nil
}

// pickFrom shows a numbered list on the terminal (not stdout, which may be
// redirected) and returns the chosen index. Empty input or Ctrl-D cancels,
// or returns -1 when optional is set.
func pickFrom(header string, items []string, what string, optional bool) (int, error) {
	t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return -1, err
	}
	defer t.Close()
	if header != "" {
		fmt.Fprintln(t, header)
	}
	w := len(strconv.Itoa(len(items)))
	for i, n := range items {
		fmt.Fprintf(t, "%*d  %s\n", w, i+1, n)
	}
	hint := ", Enter to cancel"
	if optional {
		hint = ""
	}
	r := bufio.NewReader(t)
	for {
		fmt.Fprintf(t, "%s [1-%d%s]: ", what, len(items), hint)
		line, rerr := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if rerr != nil { // Ctrl-D: move off the prompt line
				fmt.Fprintln(t)
			}
			if optional {
				return -1, nil
			}
			return -1, errors.New("cancelled")
		}
		if i, err := strconv.Atoi(line); err == nil && i >= 1 && i <= len(items) {
			return i - 1, nil
		}
		fmt.Fprintln(t, "invalid choice")
	}
}

// cmdRemove deletes an entry after confirmation. It needs no password or
// YubiKey: anyone who can write to the store can delete files anyway.
func cmdRemove(name string, force bool) error {
	canon, path, err := entry(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: no such entry", canon)
	}
	if !force {
		ans, err := prompt(fmt.Sprintf("Remove %s? [y/N]: ", canon))
		if err != nil && ans == "" && !errors.Is(err, io.EOF) {
			return fmt.Errorf("cannot ask for confirmation, use -f: %w", err)
		}
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return errors.New("cancelled")
		}
	}
	rel := filepath.FromSlash(canon) + ".yks"
	k, kerr := readHeaderKDF(path)
	tracked := gitTracked(rel)
	if err := os.Remove(path); err != nil {
		return err
	}
	if kerr == nil {
		cacheDrop(entryCacheID(k, canon)) // forget an entry-specific cached key
	}
	// Remove parent folders that are now empty, never the store itself.
	root := filepath.Clean(storeDir())
	for d := filepath.Dir(path); strings.HasPrefix(d, root+string(filepath.Separator)); d = filepath.Dir(d) {
		if os.Remove(d) != nil { // fails when not empty
			break
		}
	}
	if tracked {
		gitAuto("yks: remove "+canon, rel)
	}
	fmt.Fprintf(os.Stderr, "removed %s\n", canon)
	return nil
}

// gitTracked reports whether auto-commit is on and git tracks rel, so that
// removing an untracked entry does not produce a failing commit.
func gitTracked(rel string) bool {
	if os.Getenv("YKS_GIT") != "1" {
		return false
	}
	return exec.Command("git", "-C", storeDir(), "ls-files", "--error-unmatch", "--", rel).Run() == nil
}

// ---------- encrypt / decrypt ----------

func cmdEncrypt(name, in string, slot int, force bool) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if slot == 0 {
		slot = c.Slot
	}
	canon, path, err := entry(name)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	existed := statErr == nil
	if existed && !force {
		return fmt.Errorf("%s exists (use -f to overwrite)", canon)
	}
	data, err := readInput(canon, in)
	if err != nil {
		return err
	}
	defer clear(data)
	if _, err := device(); err != nil { // choose the key before the password prompt
		return err
	}
	// Protects against e.g. `failing-cmd | yks -f e name` wiping an entry.
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("refusing to store an empty secret (input was empty or whitespace only)")
	}
	pk, err := passKey(c.KDF, true)
	if err != nil {
		return err
	}
	defer clear(pk)
	out, _, err := sealEntry(pk, c.KDF, slot, "", canon, data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(path, out); err != nil {
		return err
	}
	verb := "add"
	if existed {
		verb = "update"
	}
	gitAuto(fmt.Sprintf("yks: %s %s", verb, canon), filepath.FromSlash(canon)+".yks")
	return nil
}

// gitAuto commits the given paths (relative to the store) when YKS_GIT=1 and
// the store is a git repository. Failures are warnings: the entry is already
// safely written.
func gitAuto(msg string, paths ...string) {
	if os.Getenv("YKS_GIT") != "1" {
		return
	}
	root := storeDir()
	warn := func(s string) { fmt.Fprintln(os.Stderr, "yks: warning: git auto-commit skipped:", s) }
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		warn("store is not a git repository (run: git -C " + root + " init)")
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		warn("git not found")
		return
	}
	add := append([]string{"-C", root, "add", "-A", "--"}, paths...)
	commit := append([]string{"-C", root, "commit", "-q", "-m", msg, "--"}, paths...)
	for _, args := range [][]string{add, commit} {
		cmd := exec.Command("git", args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			warn(fmt.Sprintf("'git %s' failed: %v", args[2], err))
			return
		}
	}
}

// cmdDecrypt writes the entry to stdout, or with clip copies its first line
// (whole entry with all) to the clipboard.
func cmdDecrypt(name string, clip, all bool) error {
	canon, path, err := entry(name)
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
	if _, err := device(); err != nil { // choose the key before the password prompt
		return err
	}
	pt, err := openWithRetry(canon, k, slot, seed, nonce, b[hdrLen:], aad(b[:hdrLen], canon))
	if err != nil {
		return err
	}
	defer clear(pt)
	if !clip {
		_, err = os.Stdout.Write(pt)
		return err
	}
	if all {
		if !utf8.Valid(pt) || bytes.IndexByte(pt, 0) >= 0 {
			return fmt.Errorf("%s is binary and cannot go to the clipboard; use: yks d %s > file", canon, canon)
		}
		n := bytes.Count(bytes.TrimRight(pt, "\n"), []byte("\n")) + 1
		return clipCopy(pt, fmt.Sprintf("entire entry (%d lines)", n))
	}
	line, _, _ := bytes.Cut(pt, []byte("\n"))
	return clipCopy(bytes.TrimRight(line, "\r"), "first line")
}

// sealEntry encrypts pt as entry canon with a fresh seed and nonce. It also
// returns the AEAD so callers can verify what was written without another
// YubiKey operation.
func sealEntry(pk []byte, k kdf, slot int, dev, canon string, pt []byte) ([]byte, cipher.AEAD, error) {
	seed, nonce := randBytes(seedLen), randBytes(nonceLen)
	hdr := header(slot, k, seed, nonce)
	aead, err := newAEAD(pk, seed, slot, dev)
	if err != nil {
		return nil, nil, err
	}
	return aead.Seal(append([]byte{}, hdr...), nonce, pt, aad(hdr, canon)), aead, nil
}

func header(slot int, k kdf, seed, nonce []byte) []byte {
	h := append([]byte(magic), byte(slot))
	h = append(h, k.bytes()...)
	h = append(h, seed...)
	return append(h, nonce...)
}

// readHeaderKDF reads only the header of an entry file.
func readHeaderKDF(path string) (kdf, error) {
	f, err := os.Open(path)
	if err != nil {
		return kdf{}, err
	}
	defer f.Close()
	b := make([]byte, hdrLen+16)
	if _, err := io.ReadFull(f, b); err != nil {
		return kdf{}, errors.New("file too short")
	}
	_, k, _, _, err := parseHeader(b)
	return k, err
}

func parseHeader(b []byte) (int, kdf, []byte, []byte, error) {
	if len(b) < hdrLen+16 || string(b[:4]) != magic {
		return 0, kdf{}, nil, nil, errors.New("not a yks file")
	}
	slot := int(b[4])
	k := kdf{T: binary.BigEndian.Uint32(b[5:9]), M: binary.BigEndian.Uint32(b[9:13]), P: b[13], Salt: b[14:30]}
	if (slot != 1 && slot != 2) || !k.valid() {
		return 0, kdf{}, nil, nil, errors.New("corrupt header")
	}
	return slot, k, b[30:62], b[62:74], nil
}

// The entry name is authenticated so files cannot be swapped between entries.
func aad(hdr []byte, canon string) []byte {
	return append(append(append([]byte{}, hdr...), 0), canon...)
}

// newAEAD derives the file key; dev selects a YubiKey by serial ("" = YKS_DEVICE or the only one).
func newAEAD(pk, seed []byte, slot int, dev string) (cipher.AEAD, error) {
	m := hmac.New(sha256.New, pk)
	m.Write([]byte("yks-v1 challenge"))
	m.Write(seed)
	resp, err := challengeResponse(slot, m.Sum(nil), dev)
	if err != nil {
		return nil, err
	}
	ikm := append(resp, pk...)
	defer clear(ikm)
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, seed, []byte("yks-v1 aes-256-gcm")), key); err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Uses `ykman [--device SERIAL] otp calculate <slot> <hex>`. The challenge is
// passed as an argument (visible in /proc), which is fine here: it is a one-way
// function of pk, and the response alone does not yield the key.
// Set YKS_DEVICE=<serial> to pick a specific YubiKey when several are plugged in.
func challengeResponse(slot int, chal []byte, dev string) ([]byte, error) {
	if dev == "" {
		d, err := device()
		if err != nil {
			return nil, err
		}
		dev = d
	}
	cmd := ykmanOn(dev, "otp", "calculate", strconv.Itoa(slot), hex.EncodeToString(chal))
	cmd.Stderr = os.Stderr // ykman prints its own "Touch your YubiKey..." prompt here
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ykman otp calculate failed (slot %d configured for challenge-response?): %w", slot, err)
	}
	resp, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(resp) != 20 {
		return nil, errors.New("unexpected ykman output (expected 40 hex chars)")
	}
	return resp, nil
}

// ---------- password / input ----------

func cacheTTL() int {
	if v, err := strconv.Atoi(os.Getenv("YKS_CACHE_TTL")); err == nil {
		return v
	}
	return 300
}

const maxTries = 3

// entryCacheID names the cache slot for an entry whose master password
// differs from the store-wide cached one. The name is hashed so the agent
// never sees entry names (they may also contain spaces).
func entryCacheID(k kdf, canon string) string {
	h := sha256.Sum256([]byte(canon))
	return k.cacheID() + ":" + hex.EncodeToString(h[:6])
}

// openWithRetry decrypts an entry, trying cached keys first (entry-specific,
// then store-wide) and then asking for the master password up to maxTries
// times. Keys are cached only after they opened an entry, so a typo is never
// cached. A password that differs from the store-wide one is cached for this
// entry only, so it does not displace the key used by all other entries.
// Every attempt costs one YubiKey operation (one touch with --touch).
func openWithRetry(canon string, k kdf, slot int, seed, nonce, body, ad []byte) ([]byte, error) {
	open := func(pk []byte) ([]byte, error) {
		aead, err := newAEAD(pk, seed, slot, "")
		if err != nil {
			return nil, err // YubiKey problem: retrying the password will not help
		}
		pt, err := aead.Open(nil, nonce, body, ad)
		if err != nil {
			return nil, nil
		}
		return pt, nil
	}
	sid, eid := k.cacheID(), entryCacheID(k, canon)
	sPK, ePK := cacheGet(sid), cacheGet(eid)
	defer clear(sPK)
	defer clear(ePK)

	for _, pk := range [][]byte{ePK, sPK} {
		if pk == nil {
			continue
		}
		pt, err := open(pk)
		if err != nil || pt != nil {
			return pt, err
		}
	}
	if ePK != nil {
		cacheDrop(eid) // stale: the entry was re-encrypted since
	}
	if sPK != nil || ePK != nil {
		fmt.Fprintf(os.Stderr, "the cached master password does not open %s\n", canon)
	}

	for try := 1; try <= maxTries; try++ {
		pw, err := readSecret(fmt.Sprintf("Master password for %s: ", canon))
		if err != nil {
			return nil, err
		}
		pk := argon2.IDKey(pw, k.Salt, k.T, k.M, k.P, 32)
		clear(pw)
		pt, err := open(pk)
		if err != nil {
			clear(pk)
			return nil, err
		}
		if pt != nil {
			switch {
			case sPK == nil:
				cachePut(sid, pk, cacheTTL())
			case !hmac.Equal(pk, sPK):
				cachePut(eid, pk, cacheTTL())
			}
			clear(pk)
			return pt, nil
		}
		clear(pk)
		if try < maxTries {
			fmt.Fprintf(os.Stderr, "wrong master password (or YubiKey), try again (%d/%d)\n", try, maxTries)
		}
	}
	return nil, fmt.Errorf("decryption failed after %d attempts: wrong master password or YubiKey, or the file was tampered with or renamed", maxTries)
}

// passKey returns the store-wide key for encryption: cached, or asked for
// (twice when confirm is set) and then cached.
func passKey(k kdf, confirm bool) ([]byte, error) {
	id := k.cacheID()
	if pk := cacheGet(id); pk != nil {
		return pk, nil
	}
	pw, err := readSecret("Master password (may be empty): ")
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	if confirm {
		pw2, err := readSecret("Retype master password: ")
		if err != nil {
			return nil, err
		}
		ok := bytes.Equal(pw, pw2)
		clear(pw2)
		if !ok {
			return nil, errors.New("passwords do not match")
		}
	}
	pk := argon2.IDKey(pw, k.Salt, k.T, k.M, k.P, 32)
	cachePut(id, pk, cacheTTL())
	return pk, nil
}

func readInput(name, in string) ([]byte, error) {
	if in != "" {
		return os.ReadFile(in)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return io.ReadAll(os.Stdin)
	}
	a, err := readSecret("Secret for " + name + ": ")
	if err != nil {
		return nil, err
	}
	b, err := readSecret("Retype secret: ")
	if err != nil {
		clear(a)
		return nil, err
	}
	defer clear(b)
	if !bytes.Equal(a, b) {
		clear(a)
		return nil, errors.New("secrets do not match")
	}
	return a, nil
}

func readSecret(p string) ([]byte, error) {
	t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	fmt.Fprint(t, p)
	b, err := term.ReadPassword(int(t.Fd()))
	fmt.Fprintln(t)
	return b, err
}

func prompt(p string) (string, error) {
	t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer t.Close()
	fmt.Fprint(t, p)
	return bufio.NewReader(t).ReadString('\n')
}

// ---------- version ----------

// version can be set at build time: -ldflags "-X main.version=v1.2.3".
// Otherwise the module version recorded by `go install ...@vX.Y.Z` is used.
var version = ""

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version // "(devel)" for a local build
	}
	return "unknown"
}

// ---------- dependencies ----------

const (
	hintYkman = "install YubiKey Manager: 'brew install ykman' (macOS), 'apt install yubikey-manager' (Debian/Ubuntu), 'dnf install yubikey-manager' (Fedora), 'pacman -S yubikey-manager' (Arch)"
	hintClip  = "install 'wl-clipboard' (Wayland) or 'xclip' (X11); macOS has pbcopy built in"
)

// ykman builds an ykman command that needs no particular YubiKey.
func ykman(args ...string) *exec.Cmd { return ykmanOn("", args...) }

// ykmanOn targets the YubiKey with serial dev ("" = let ykman choose).
func ykmanOn(dev string, args ...string) *exec.Cmd {
	if dev != "" {
		args = append([]string{"--device", dev}, args...)
	}
	return exec.Command("ykman", args...)
}

// requireDeps fails fast, before any password prompt, if a needed tool is missing.
func requireDeps(clip bool) error {
	var missing []string
	if _, err := exec.LookPath("ykman"); err != nil {
		missing = append(missing, "ykman: "+hintYkman)
	}
	if clip {
		if _, _, err := clipTool(); err != nil {
			missing = append(missing, "clipboard tool: "+hintClip)
		}
	}
	if len(missing) > 0 {
		return errors.New("missing dependencies (run 'yks check' for details):\n  - " + strings.Join(missing, "\n  - "))
	}
	return nil
}

// cmdCheck reports on everything yks needs. Clipboard and agent are warnings
// only; a missing ykman, YubiKey or store is a failure.
func cmdCheck() error {
	failed := false
	report := func(state, what, detail string) {
		if state == "FAIL" {
			failed = true
		}
		fmt.Printf("[%-4s] %-10s %s\n", state, what, detail)
	}

	report("ok", "yks", versionString())
	var otpInfo string
	if _, err := exec.LookPath("ykman"); err != nil {
		report("FAIL", "ykman", "not found; "+hintYkman)
	} else {
		v, _ := ykman("--version").Output()
		report("ok", "ykman", strings.TrimSpace(string(v)))
		keys, err := listYubiKeys()
		def, src := defaultDevice()
		target := def
		switch {
		case err != nil:
			report("FAIL", "yubikey", err.Error())
		case len(keys) == 0:
			report("FAIL", "yubikey", "none connected")
		default:
			found := false
			for _, k := range keys {
				report("ok", "yubikey", k.desc)
				found = found || (def != "" && k.serial == def)
			}
			switch {
			case def != "" && !found:
				report("warn", "device", fmt.Sprintf("default YubiKey %s (from %s) is not connected", def, src))
				target = ""
			case def != "":
				report("ok", "device", fmt.Sprintf("default %s (from %s)", def, src))
			case len(keys) > 1:
				report("warn", "device", "several connected and no default: yks asks each time; set -d, YKS_DEVICE or device= in .config")
			}
			if target != "" || len(keys) == 1 {
				out, err := ykmanOn(target, "otp", "info").CombinedOutput()
				info := strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " | ")), " ")
				if err != nil {
					report("FAIL", "otp", "not usable: "+info)
				} else {
					otpInfo = string(out)
					report("ok", "otp", info)
				}
			}
		}
	}

	if cp, _, err := clipTool(); err != nil {
		report("warn", "clipboard", "none found, 'c' will not work; "+hintClip)
	} else {
		report("ok", "clipboard", cp[0])
	}

	if c, err := loadConfig(); err != nil {
		report("FAIL", "store", err.Error())
	} else {
		report("ok", "store", fmt.Sprintf("%s (default slot %d)", storeDir(), c.Slot))
		_, gerr := os.Stat(filepath.Join(storeDir(), ".git"))
		_, lerr := exec.LookPath("git")
		auto := os.Getenv("YKS_GIT") == "1"
		switch {
		case gerr == nil && auto && lerr != nil:
			report("warn", "git", "YKS_GIT=1 but git is not installed")
		case gerr == nil && auto:
			report("ok", "git", "repository found, auto-commit on")
		case gerr == nil:
			report("ok", "git", "repository found, auto-commit off (set YKS_GIT=1 to enable)")
		case auto:
			report("warn", "git", "YKS_GIT=1 but the store is not a git repository")
		}
		if c.KDF.M < defaultArgonMiB*1024 || c.KDF.T < defaultArgonT {
			report("warn", "argon2", fmt.Sprintf("store uses %d MiB, t=%d; recommended at least %d MiB, t=%d: run 'yks rekey -m %d -t %d'",
				c.KDF.M/1024, c.KDF.T, defaultArgonMiB, defaultArgonT, defaultArgonMiB, defaultArgonT))
		} else {
			report("ok", "argon2", fmt.Sprintf("%d MiB, t=%d, p=%d", c.KDF.M/1024, c.KDF.T, c.KDF.P))
		}
		if names, err := listEntries(); err == nil {
			weak, bad := 0, 0
			for _, n := range names {
				_, path, _ := entry(n)
				k, err := readHeaderKDF(path)
				switch {
				case err != nil:
					bad++
				case k.M < c.KDF.M || k.T < c.KDF.T:
					weak++
				}
			}
			switch {
			case bad > 0:
				report("FAIL", "entries", fmt.Sprintf("%d of %d entries have an unreadable header", bad, len(names)))
			case weak > 0:
				report("warn", "entries", fmt.Sprintf("%d of %d entries use weaker Argon2id settings than .config: run 'yks rekey'", weak, len(names)))
			default:
				report("ok", "entries", fmt.Sprintf("%d, all at current settings", len(names)))
			}
		}
		for _, l := range strings.Split(otpInfo, "\n") {
			if strings.HasPrefix(l, fmt.Sprintf("Slot %d:", c.Slot)) && strings.Contains(l, "empty") {
				report("FAIL", "slot", fmt.Sprintf("default slot %d is empty; see 'YubiKey setup' in README", c.Slot))
			}
		}
	}

	if p, err := sockPath(); err != nil {
		report("warn", "agent", "password cache unavailable: "+err.Error())
	} else if _, err := agentReq("GET -", nil); err == nil {
		report("ok", "agent", "running ("+p+")")
	} else {
		report("ok", "agent", "not running (starts automatically when needed)")
	}

	if failed {
		return errors.New("some checks failed")
	}
	return nil
}

// ---------- clipboard ----------

func clipTool() (cp, paste []string, err error) {
	has := func(c string) bool { _, e := exec.LookPath(c); return e == nil }
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "" && has("wl-copy") && has("wl-paste"):
		return []string{"wl-copy"}, []string{"wl-paste", "-n"}, nil
	case has("xclip"):
		return []string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}, nil
	case has("pbcopy") && has("pbpaste"):
		return []string{"pbcopy"}, []string{"pbpaste"}, nil
	}
	return nil, nil, errors.New("no clipboard tool found (wl-copy, xclip or pbcopy)")
}

func clipSet(data []byte) error {
	cp, _, err := clipTool()
	if err != nil {
		return err
	}
	if data == nil && cp[0] == "wl-copy" {
		return exec.Command("wl-copy", "--clear").Run()
	}
	cmd := exec.Command(cp[0], cp[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	return cmd.Run()
}

// clipCopy sets the clipboard and spawns a detached copy of itself that clears
// it after clipTTL, but only if it still holds our secret (passed via a pipe).
func clipCopy(s []byte, what string) error {
	if err := clipSet(s); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "__clipclear")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = in.Write(s)
	_ = in.Close()
	fmt.Fprintf(os.Stderr, "copied %s to clipboard, clearing in %s\n", what, clipTTL)
	return cmd.Process.Release()
}

func clipClearChild() {
	s, _ := io.ReadAll(os.Stdin)
	defer clear(s)
	time.Sleep(clipTTL)
	_, paste, err := clipTool()
	if err != nil {
		return
	}
	cur, _ := exec.Command(paste[0], paste[1:]...).Output()
	// Clipboard tools may add or drop a final newline; ignore that difference.
	if bytes.Equal(bytes.TrimRight(cur, "\r\n"), bytes.TrimRight(s, "\r\n")) {
		_ = clipSet(nil)
	}
	clear(cur)
}

// ---------- helpers ----------

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		die(err)
	}
	return b
}

func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*") // created with mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
