# yks — YubiKey-backed secret store

[![ci](https://github.com/fruh/yks/actions/workflows/ci.yml/badge.svg)](https://github.com/fruh/yks/actions/workflows/ci.yml)

`yks` is a small command-line tool that encrypts secrets and files with a key derived from **two factors**: an optional master password and a YubiKey HMAC-SHA1 challenge-response slot. It stores entries as individual encrypted files in a directory, similar to [`pass`](https://www.passwordstore.org/), without needing GPG.

- AES-256-GCM authenticated encryption
- Argon2id password hashing (256 MiB by default)
- `yks rekey` to change password, slot, YubiKey or Argon2 settings for the whole store, safely
- A separate key for every file
- Master key cached in RAM only by a self-starting background agent, with a timeout
- Runs on Linux and macOS
- Clipboard copy that clears itself automatically

---

## Table of contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [YubiKey setup](#yubikey-setup)
4. [Quick start](#quick-start)
5. [Commands](#commands)
6. [Environment variables](#environment-variables)
7. [Re-encrypting the store (rekey)](#re-encrypting-the-store-rekey)
8. [Storage layout](#storage-layout)
9. [Storing metadata](#storing-metadata)
10. [Cryptographic design](#cryptographic-design)
11. [File format](#file-format)
12. [Password caching](#password-caching)
13. [Security model](#security-model)
14. [Backup and recovery](#backup-and-recovery)
15. [Troubleshooting](#troubleshooting)
16. [Limitations](#limitations)

---

## Requirements

| Dependency | Purpose |
|---|---|
| Go ≥ 1.22 | installing / building |
| `ykman` (YubiKey Manager CLI) | challenge-response with the YubiKey |
| `wl-copy`/`wl-paste` (Wayland), `xclip` (X11) or `pbcopy`/`pbpaste` (macOS) | the `c` command only |
| Linux or macOS | the only supported platforms |

Install `ykman`:

```sh
# Debian/Ubuntu
sudo apt install yubikey-manager
# Fedora
sudo dnf install yubikey-manager
# Arch
sudo pacman -S yubikey-manager
# macOS
brew install ykman
```

---

## Installation

### With `go install` (recommended)

```sh
go install github.com/fruh/yks@latest
```

This builds the binary and places it in `$(go env GOPATH)/bin`, usually `~/go/bin`. Make sure that folder is on your `PATH`:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"     # add to ~/.zshrc or ~/.bashrc
yks version
```

To install a specific release instead of the latest, use its tag: `go install github.com/fruh/yks@v0.1.0`. Run the same command again to upgrade.

Only Linux and macOS are supported. On other systems the build fails with `build constraints exclude all Go files`.

### From source

```sh
git clone https://github.com/fruh/yks.git
cd yks
go build -o yks .
sudo install -m 0755 yks /usr/local/bin/
```

A plain `go build` is all you need. The optional flags below produce a smaller, cleaner binary and are recommended for the copy you actually install.

### Optional build flags

Recommended release build:

```sh
go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" -o yks .
```

| Flag | Effect | Why use it |
|---|---|---|
| `-trimpath` | Removes local file paths (such as `/Users/alice/code/yks/main.go`) from the binary | The binary does not reveal your username or folder layout, and builds of the same source are identical on any machine |
| `-ldflags="-s"` | Removes the symbol table | Smaller binary |
| `-ldflags="-w"` | Removes debugging information | Smaller binary; together with `-s`, typically about 25–30% |
| `-ldflags="-X main.version=…"` | Sets the version printed by `yks version` | Without it, a local build reports `(devel)`; `go install …@vX.Y.Z` sets the version automatically |

What you give up: you cannot step through the binary in a debugger such as Delve. Crash messages still show function names, only without full file paths. `yks version` keeps working either way, because Go stores the version information separately from what `-s -w` removes.

Stripping is **not** a security measure. It does not meaningfully hinder reverse engineering; the benefits are privacy (no leaked paths), size and reproducible builds.

**Fully static binary (Linux, optional).** With `CGO_ENABLED=0` the binary does not depend on the system C library and runs on any Linux distribution. This is handy if you copy it between machines:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o yks .
```

On macOS this makes no difference, so leave it out there.

**The same flags with `go install`:**

```sh
go install -trimpath -ldflags="-s -w" github.com/fruh/yks@latest
CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" github.com/fruh/yks@latest   # Linux, static
```

Without the flags, `go install` still works. The binary then contains paths from Go's module cache (`~/go/pkg/mod/...`) rather than your own project folder.

**Which build to use:**

| Situation | Command |
|---|---|
| Changing the code | `go build -o yks .` |
| Installing on your machine | `go build -trimpath -ldflags="-s -w" -o yks .` |
| Copying to other Linux machines | `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o yks .` |
| Installing from GitHub | `go install -trimpath -ldflags="-s -w" github.com/fruh/yks@latest` |

### Verify

```sh
yks version
yks check
```

### Repository layout

| File | Contents |
|---|---|
| `main.go` | CLI, key derivation, encryption, storage, clipboard, dependency checks |
| `agent.go` | in-memory password cache agent (client and server) |
| `rekey.go` | `yks rekey`: re-encrypt, verify and swap the whole store |
| `sys_linux.go` | peer-UID check and process hardening (Linux) |
| `sys_darwin.go` | peer-UID check and process hardening (macOS) |
| `go.mod`, `go.sum` | module definition and dependency checksums |
| `.github/workflows/ci.yml` | builds, vets and format-checks on Linux and macOS |
| `LICENSE` | MIT |

---

## YubiKey setup

Slot 1 usually holds the factory Yubico OTP credential. Slot 2 is normally free, so it is the usual choice. **Programming a slot overwrites whatever was in it.**

Check the current state of the slots:

```sh
ykman otp info
```

Program slot 2 for HMAC-SHA1 challenge-response. **Choose one of the two options below.**

**Option A — random secret generated on the key.** The secret is never shown, so you cannot back it up or copy it to a second YubiKey:

```sh
ykman otp chalresp --generate --touch 2
```

**Option B — your own secret (recommended).** This lets you back up the secret and program a spare key. See [Backup and recovery](#backup-and-recovery):

```sh
SECRET=$(head -c 20 /dev/urandom | xxd -p -c 40)
echo "$SECRET"          # write this down / store offline, then clear your terminal
ykman otp chalresp --touch 2 "$SECRET"
```

`--touch` makes every operation wait for a physical tap on the key. This is strongly recommended, because it stops malware from silently using the key while it is plugged in.

Test the slot:

```sh
ykman otp calculate 2 $(head -c 32 /dev/urandom | xxd -p -c 64)
# → 40 hex characters
```

---

## Quick start

```sh
yks check                         # verify ykman, YubiKey, clipboard
yks init                          # create ~/.ykstore, choose default slot (Argon2id 256 MiB, t=3)
yks e github/personal             # type a secret (hidden, entered twice)
yks c github/personal             # copy it to the clipboard for 45 s
yks d github/personal             # print it to stdout
yks c                             # pick an entry from a numbered list
yks rm github/personal            # remove an entry (asks for confirmation)
yks ls                            # list all entries
```

---

## Commands

```
yks [-s 1|2] [-f] [-a] <command> [args]
```

Flags can go before or after the command, in any order. These are all the same:

```sh
yks -a c github/personal
yks c -a github/personal
yks c github/personal -a
```

`--` ends flag parsing, for an entry whose name starts with `-`: `yks d -- -odd-name`. Anything else starting with `-` that is not a known flag is rejected as a typo rather than treated as an entry name.

| Command | Description |
|---|---|
| `init [-m MiB] [-t N]` | Creates the store directory and `.config`, and asks for the default slot (or takes it from `-s`). `-m` sets Argon2id memory (default 256 MiB), `-t` its iterations (default 3). |
| `e <name> [file]` | Encrypts into entry `<name>`. The input is `file` if given; otherwise piped stdin; otherwise a hidden prompt, entered twice. Empty or whitespace-only input is refused, so a failed pipe cannot wipe an entry. |
| `d [name]` | Decrypts an entry to stdout. Without a name, shows a numbered list and asks which one. |
| `c [name]` | Decrypts an entry and copies its **first line** to the clipboard, or the **entire entry** with `-a`. The clipboard is cleared after 45 seconds, if it still contains the secret. Without a name, shows a numbered list and asks which one. |
| `rm [name]` | Removes an entry after asking `Remove <name>? [y/N]`. Without a name, shows a numbered list and asks which one. Needs no password or YubiKey. See [Removing entries](#removing-entries). |
| `ls` | Lists all entries. |
| `forget` | Stops the cache agent immediately, wiping all cached keys. |
| `check` | Checks dependencies, the YubiKey, the store and the agent, and reports what is missing. |
| `rekey [-p] [-s 1\|2] [-d serial] [-m MiB] [-t N]` | Re-encrypts every entry with the current or new settings. See [Re-encrypting the store](#re-encrypting-the-store-rekey). |
| `version` | Prints the version (the release tag when installed with `go install ...@vX.Y.Z`). |

| Flag | Description |
|---|---|
| `-s 1\|2` | YubiKey slot for a **new** entry (overrides the config default). Decryption always uses the slot recorded in the file. |
| `-f` | Allows `e` to overwrite an existing entry; makes `rm` skip the confirmation. |
| `-a` | Makes `c` copy the entire entry instead of the first line. Only valid with `c`. |

### Dependency checks

Before `e`, `d` or `c` does anything else — before asking for a password — `yks` checks that the tools it needs are installed:

| Command | Needs |
|---|---|
| `e`, `d` | `ykman` |
| `c` | `ykman` and a clipboard pair: `wl-copy` + `wl-paste` (Wayland), `xclip` (X11) or `pbcopy` + `pbpaste` (macOS) |

If something is missing, it stops with install instructions:

```
yks: missing dependencies (run 'yks check' for details):
  - ykman: install YubiKey Manager: 'brew install ykman' (macOS), ...
```

`yks check` runs a full diagnosis and exits with an error if anything essential fails:

```
$ yks check
[ok  ] ykman      YubiKey Manager (ykman) version: 5.5.1
[ok  ] yubikey    Slot 1: programmed | Slot 2: programmed
[ok  ] clipboard  pbcopy
[ok  ] store      /Users/alice/.ykstore (default slot 2)
[ok  ] argon2     256 MiB, t=3, p=4
[ok  ] entries    42, all at current settings
[ok  ] agent      not running (starts automatically when needed)
```

| Check | Fails when | Level |
|---|---|---|
| ykman | not installed | FAIL |
| yubikey | not plugged in, not readable, or several keys connected without `YKS_DEVICE` | FAIL |
| slot | the default slot from `.config` is empty | FAIL |
| store | `yks init` not run, or `.config` is invalid | FAIL |
| entries | an entry's header cannot be read | FAIL |
| argon2 | the store's settings are below the recommended 256 MiB, t=3 | warn |
| entries | some entries use weaker Argon2id settings than `.config` (fix with `yks rekey`) | warn |
| clipboard | no clipboard tool (only `c` is affected) | warn |
| agent | the socket folder is insecure (caching is disabled) | warn |
| git | `YKS_GIT=1` is set but the store is not a git repository, or git is not installed | warn |

`ykman` only reports whether a slot is *programmed*, not whether it holds a challenge-response credential. A slot holding Yubico OTP passes `check`, but decryption then fails with `ykman otp calculate failed`.

### Copying to the clipboard

`c` follows the `pass` convention: it copies only the **first line**, which by convention holds the secret, and leaves the metadata lines below it out. With `-a`, it copies the **entire entry**, for multi-line secrets such as SSH keys, certificates or recovery codes:

```
$ yks c github/personal
copied first line to clipboard, clearing in 45s

$ yks -a c ssh/deploy-key
copied entire entry (27 lines) to clipboard, clearing in 45s

$ yks -a c                      # pick from the list, copy everything
```

- A trailing `\r` (Windows line endings) is removed from the first line; with `-a`, the content is copied exactly as stored.
- The clipboard is cleared after 45 seconds either way, if it still holds what `yks` put there.
- Binary entries are refused with `-a` (clipboards hold text); use `yks d name > file` instead.

### Removing entries

```
$ yks rm
1  docs/passport
2  github/personal
3  mail/old
Entry [1-3, Enter to cancel]: 3
Remove mail/old? [y/N]: y
removed mail/old
```

- Only `y` or `yes` removes the entry; anything else, including just Enter or Ctrl-D, cancels.
- `yks -f rm mail/old` skips the question, for scripts. Without `-f` and without a terminal to ask on, `rm` refuses.
- No password or YubiKey is needed: anyone who can write to the store folder can delete files anyway.
- Folders left empty by the removal are deleted too (never the store itself).
- A key cached for that entry alone (see [Wrong password and entries with a different password](#wrong-password-and-entries-with-a-different-password)) is dropped from the agent.
- With `YKS_GIT=1`, the removal is committed as `yks: remove <name>` if git tracked the entry.

The file is deleted normally, not overwritten. That is fine because it only ever contained ciphertext, but copies elsewhere remain: backups, and **git history**, from which the entry can still be restored (see [History with git](#history-with-git)).

### Picking an entry from a list

Run `d`, `c` or `rm` without a name to choose from a numbered list:

```
$ yks c
1  docs/passport
2  github/personal
3  mail/work
Entry [1-3, Enter to cancel]: 2
copied first line to clipboard, clearing in 45s
```

- Entries are sorted alphabetically, the same order as `yks ls`.
- Press Enter on an empty line, or Ctrl-D, to cancel.
- An invalid number asks again.
- The list and prompt go to the terminal, not stdout, so redirecting still works: `yks d > passport.pdf` shows the list on screen and writes only the decrypted file.

Examples:

```sh
# Generate and store a password
pwgen -s 32 1 | yks e mail/work

# Encrypt a file, then restore it
yks e docs/passport passport.pdf
yks d docs/passport > passport.pdf

# Multi-line entry with metadata
printf 'S3cr3t!\nuser: alice\nurl: https://example.com\n' | yks e web/example

# Use slot 1 for this entry only
yks -s 1 e test/slot1

# Replace an existing entry
yks -f e mail/work

# Use in scripts
export DB_PASSWORD="$(yks d prod/db | head -n1)"
```

Entry names:

- may contain `/` to create folders (`work/aws/root`)
- may be given with or without the `.yks` suffix
- must not be absolute or start with `.`, and must not escape the store with `..`

---

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `YKS_DIR` | `~/.ykstore` | Store location |
| `YKS_CACHE_TTL` | `300` | Seconds to cache the master key; `0` turns caching off |
| `YKS_DEVICE` | *(none)* | YubiKey serial to use when several are connected (see `ykman list --serials`) |
| `YKS_GIT` | *(off)* | `1` commits every change automatically if the store is a git repository (see [History with git](#history-with-git)) |

---

## Re-encrypting the store (rekey)

`yks rekey` re-encrypts every entry in one go. Use it to:

| Goal | Command |
|---|---|
| Upgrade old entries to the current `.config` settings | `yks rekey` |
| Raise the Argon2id cost | `yks rekey -m 512 -t 4` |
| Change the master password | `yks rekey -p` |
| Move to the other slot | `yks rekey -s 1` |
| Move to a different YubiKey (both plugged in) | `YKS_DEVICE=<old serial> yks rekey -d <new serial>` |

Options can be combined, for example `yks rekey -p -m 512`.

| Option | Meaning |
|---|---|
| `-p` | Ask for a new master password (entered twice) |
| `-s 1\|2` | Slot to encrypt with; also becomes the new default slot |
| `-d serial` | YubiKey to encrypt with; decryption uses `YKS_DEVICE` or the only connected key |
| `-m MiB` | New Argon2id memory, 8–4096 MiB |
| `-t N` | New Argon2id iterations, 1–20 |

What happens:

1. You always type the current master password, even if it is cached: the cache holds only derived keys, and a new salt needs the password itself. If some entries use a different password, `rekey` asks for it when it reaches the first such entry (up to 3 attempts) and remembers it for the rest of the run. Every password that has worked is tried on each later entry, one YubiKey operation each. At the end, all entries use the same (new or current) password.
2. A fresh store salt is generated every time.
3. Everything that is not an entry (`.git`, other files) is copied into a new directory next to the store, for example `~/.ykstore.rekey-123456`.
4. Each entry is decrypted, re-encrypted into the new directory, then read back from disk and checked against the original plaintext.
5. Only when **every** entry has succeeded is the old store renamed to `~/.ykstore.bak-<date>-<time>` and the new one moved into its place. Any earlier failure leaves your store untouched and deletes the temporary directory.
6. The cache agent is restarted with the new key.
7. With `YKS_GIT=1`, the result is committed. Old versions in git history keep their old keys; see [History with git](#history-with-git).

With `--touch` enabled, each entry needs **two taps**: one to decrypt, one to encrypt. Verification needs no extra tap.

After checking a few entries, delete the backup:

```sh
rm -rf ~/.ykstore.bak-20260926-141500
```

Until you do, the backup can still be decrypted with the **old** password and YubiKey secret. If you rekeyed because one of those may have leaked, delete the backup promptly, including copies in git history or other backups.

To move to a **new YubiKey secret**, rekey onto a different slot or a different key. You cannot reprogram the slot you are rekeying *from* before running `rekey`, because the old secret is needed to decrypt.

## Storage layout

```
~/.ykstore/                      (mode 0700)
├── .config                      store defaults — not secret
├── github/
│   └── personal.yks             (mode 0600)
├── mail/
│   └── work.yks
└── docs/
    └── passport.yks
```

`.config` is a plain `key=value` file:

```
slot=2
argon_t=3
argon_m=262144
argon_p=4
salt=5f1c…(32 hex chars)
```

| Key | Meaning |
|---|---|
| `slot` | Default YubiKey slot for new entries |
| `argon_t` | Argon2id iterations |
| `argon_m` | Argon2id memory in KiB (262144 = 256 MiB) |
| `argon_p` | Argon2id parallelism |
| `salt` | Store-wide Argon2 salt (16 bytes) |

Every `.yks` file contains its own copy of these parameters in its header. Each file can therefore be decrypted on its own, and `.config` only supplies defaults for **new** entries. Editing `.config` by hand affects only entries written afterwards; use [`yks rekey`](#re-encrypting-the-store-rekey) to change settings for existing entries.

All writes are atomic: the tool writes a temporary file, syncs it to disk, then renames it. An interrupted write never leaves a half-written entry.

### History with git

`yks` keeps no old versions of entries itself: overwriting an entry with `-f` replaces it. If you want history and undo, make the store a git repository. This is optional and entirely your choice.

```sh
cd ~/.ykstore
git init
git add -A && git commit -m "init"
```

**Automatic commits.** Set `YKS_GIT=1` and `yks` commits after every change:

```sh
export YKS_GIT=1      # add to ~/.zshrc or ~/.bashrc
```

| Action | Commit message | What is committed |
|---|---|---|
| `yks e name` (new entry) | `yks: add name` | that entry only |
| `yks -f e name` (overwrite) | `yks: update name` | that entry only |
| `yks rm name` | `yks: remove name` | that entry only (if git tracked it) |
| `yks rekey` | `yks: rekey N entries` | everything in the store, including `.config` |

`yks` never pushes, and uses your normal git configuration (author, commit signing, hooks). If a commit fails, you get a warning but the entry is already saved. `yks check` shows whether auto-commit is active.

**Restoring an old version:**

```sh
git -C ~/.ykstore log --oneline -- mail/work.yks        # find the version
git -C ~/.ykstore checkout <commit> -- mail/work.yks    # restore it
yks d mail/work                                         # check it
```

A restored entry is decrypted with the password, YubiKey and Argon2 settings that were in use **when it was written**, because each file carries its own settings. If you have run `yks rekey` since then, you need the old password and YubiKey secret for it. Afterwards, `yks check` reports it as weaker than `.config` if its settings are older; run `yks rekey` to bring it up to date.

⚠️ **Git history keeps every old secret, forever.** Every past version of every entry stays in the repository, still encrypted with the keys in use at the time. After a `yks rekey` done because a password or YubiKey secret may have leaked, the old versions in git history can still be opened with those old keys, including copies on any remote you pushed to. If that matters, start a fresh history after rekeying:

```sh
cd ~/.ykstore
rm -rf .git && git init && git add -A && git commit -m "fresh history after rekey"
# and delete or force-overwrite the remote repository
```

Only push to remotes you control. The files are encrypted, but entry names and change history are visible.

---

## Storing metadata

Everything inside an entry is encrypted, so metadata should go **inside** the entry. Use the same convention as `pass`:

```
the-actual-password
user: alice@example.com
url: https://github.com/login
otp: otpauth://totp/...
notes: recovery codes in docs/github-recovery
```

- **Line 1** is the secret. `yks c` copies only this line.
- **The remaining lines** are free-form `key: value` metadata. Read them with `yks d`.

Extracting a single field:

```sh
yks d github/personal | sed -n 's/^user: //p'
```

⚠️ **File and folder names are not encrypted.** Anyone with access to the directory can see that `bank/chase.yks` exists. If that matters, use neutral names such as `a1`, `a2`, and keep the real label inside the entry.

---

## Cryptographic design

```
pk        = Argon2id(password, store_salt, t, m, p) → 32 bytes
seed      = 32 random bytes (new for every file)
challenge = HMAC-SHA256(pk, "yks-v1 challenge" || seed) → 32 bytes
resp      = YubiKey HMAC-SHA1(slot secret, challenge)   → 20 bytes
key       = HKDF-SHA256(ikm = resp || pk, salt = seed, info = "yks-v1 aes-256-gcm") → 32 bytes
nonce     = 12 random bytes
ct        = AES-256-GCM(key, nonce, plaintext, aad = header || 0x00 || entry_name)
file      = header || ct
```

Design decisions:

- **Both factors go into the final key.** The password is part of the challenge *and* of the HKDF input. A captured challenge together with the YubiKey is therefore not enough without the password, and the password is useless without the YubiKey.
- **A separate key for each file.** A fresh random seed produces a different challenge, response and AES key for every file, including every re-encryption of the same entry.
- **The entry name is authenticated.** It is part of the GCM associated data. Swapping or renaming `.yks` files makes decryption fail, which blocks attacks that substitute one entry for another.
- **The header is authenticated.** Changing the slot, Argon2 parameters, salt, seed or nonce makes decryption fail.
- **Argon2id defaults are 256 MiB, t=3, p=4.** That is well above the OWASP minimum (19 MiB, t=2) and four times the memory of RFC 9106's memory-constrained profile (64 MiB, t=3, p=4). Thanks to the cache, you pay this about once per cache period, not per command.
- **Argon2 parameters are bounded when reading a file** (t ≤ 20, m ≤ 4 GiB, p ≤ 16). A malicious file cannot demand an unreasonable amount of work.
- **An empty password is allowed**, which leaves the YubiKey as the only factor. This is convenient but weaker.

Passing the challenge to `ykman` as a command-line argument makes it visible in `/proc`. This does not weaken the design: the challenge is a one-way function of `pk`, and the response it produces still cannot give the key without `pk`.

---

## File format

All integers are big-endian.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `YKS1` |
| 4 | 1 | YubiKey slot (1 or 2) |
| 5 | 4 | Argon2 t |
| 9 | 4 | Argon2 m (KiB) |
| 13 | 1 | Argon2 p |
| 14 | 16 | Argon2 salt |
| 30 | 32 | seed |
| 62 | 12 | GCM nonce |
| 74 | n+16 | ciphertext and 16-byte GCM tag |

The header is 74 bytes. The associated data is the 74-byte header, followed by one `0x00` byte, followed by the canonical entry name (for example `github/personal`).

---

## Password caching

A CLI process exits after every command, so it cannot hold the password in its own memory. Instead, `yks` uses a small **background agent**, similar to `ssh-agent`. The agent holds the **Argon2 output `pk`** — never the password — in RAM. You never start or install it: it starts itself when needed and stops itself when it is no longer needed.

```
yks d github/personal
  │
  ├─ ask the agent for pk ──► agent running and has it? ──yes──► use it, no prompt
  │                                     │ no
  ▼                                     │
ask password → Argon2 → pk ◄────────────┘
  │
  └─ start "yks __agent" in the background, hand it pk (valid for YKS_CACHE_TTL seconds)
                         │
          the agent answers later yks commands over a Unix socket
                         │
          all keys expired, or `yks forget` → wipe keys, delete socket, exit
```

How it works:

- **Starting.** The first command that needs `pk` and finds no agent asks for your password, creates the socket, and launches a detached copy of itself (`yks __agent`, visible in `ps`). The key is passed through a pipe, never through arguments or files. The agent is detached from the terminal, so closing the terminal does not stop it.
- **Socket location.** `$XDG_RUNTIME_DIR/yks-<uid>/agent.sock` on Linux, or `$TMPDIR/yks-<uid>/agent.sock` on macOS (`/tmp` is the fallback). The folder must be owned by you, have mode `0700` and not be a symlink; otherwise caching is refused.
- **Identity check.** Both the agent and each `yks` command check that the other side of the socket runs as your user (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS).
- **Timeout.** Each key expires `YKS_CACHE_TTL` seconds (default 300, maximum 24 h) after the password was entered; using it does not extend it. When no keys are left, the agent deletes its socket and exits.
- **Only proven keys are cached.** When decrypting, a key is cached only after it has opened an entry, so a mistyped password is never cached. (`e` caches right away, because you typed the password twice.)
- **Manual stop.** `yks forget` stops the agent at once. A reboot also ends it.
- **Disabling.** `YKS_CACHE_TTL=0` turns caching off completely; no agent is started.

To check whether the agent is running:

```sh
pgrep -fl "yks __agent"
```

When no cached key exists, `e` asks for the password twice to catch typos. `d` and `c` ask once.

### Wrong password and entries with a different password

Not every entry has to use the same master password, for example an entry imported from another store or written after `yks forget` with a different password. `d` and `c` handle this:

1. They try the cached keys first: a key cached for this specific entry, then the store-wide key.
2. If none of them opens the entry, they say so and ask for the master password. A wrong password is asked for again, up to **3 attempts**.
3. When a typed password works:
   - if nothing was cached yet, it becomes the store-wide cached key;
   - if it differs from the store-wide key, it is cached **for this entry only**, so the key used by all other entries stays in place.

```
$ yks c work/legacy
the cached master password does not open work/legacy
Master password for work/legacy: ****
wrong master password (or YubiKey), try again (1/3)
Master password for work/legacy: ****
copied first line to clipboard, clearing in 45s
```

Each attempt costs one YubiKey operation, so with `--touch` you tap once per attempt. A wrong YubiKey or a tampered file also looks like a wrong password, which is why the attempts are limited. If `ykman` itself fails (for example, no key plugged in), `yks` stops immediately instead of asking again.

New entries (`e`) always use the store-wide cached key if there is one. To write an entry with a different password, run `yks forget` first. `yks rekey` brings all entries back to one password.

---

## Security model

### What the master password protects

Checking a password guess requires the file key, and the file key requires the YubiKey's response to a challenge derived from that guess:

```
guess → pk → challenge → [YubiKey HMAC secret] → resp → key → check GCM tag
```

So the master password only becomes the last line of defence when the attacker **also** has the YubiKey's HMAC secret:

| Attacker has | Can they guess the password? |
|---|---|
| The store only | No. Without the 160-bit HMAC secret, no guess can be checked. |
| The store and the physical YubiKey | Only online: one hardware operation per guess, and one physical tap per guess with `--touch`. |
| The store and the HMAC secret (for example your offline backup of it) | Yes, offline. Each guess costs one Argon2id run, so the Argon2id settings and the password's strength decide how long this takes. |

This is why the HMAC secret backup must be kept **separate** from the master password, and why the default Argon2id cost is high.

### Why there is no per-file Argon2 salt

The Argon2 salt is shared by the whole store, so one Argon2 run covers every entry. This is deliberate and does not help an attacker:

- To recover the password, an attacker only needs to crack **one** entry; after that, every entry opens. A salt per file would not make that one entry harder, it would only make you pay Argon2 once per file.
- Salts protect against precomputed tables shared across many victims. The random store-wide salt already prevents that.
- Deriving per-file keys cheaply from a cached master key would not help either: the attacker would simply attack the master key once.

Per-file separation is still provided where it matters: every file has its own random seed, challenge, YubiKey response and AES key.

### Protected against

- Theft of the store directory, backups or the git remote. Without both the password and the YubiKey, the files are just authenticated ciphertext.
- Theft of the YubiKey alone. The attacker still needs the password.
- A leaked password alone. The attacker still needs the YubiKey.
- Leakage of one file's key. Other files use unrelated keys.
- Tampering, swapping or renaming of entry files. These are detected as decryption failures.
- Core dumps and debugger attachment. `yks` and its agent set `RLIMIT_CORE=0`, plus `PR_SET_DUMPABLE=0` on Linux (blocks ptrace and `/proc/<pid>/mem` for same-user processes) and `PT_DENY_ATTACH` on macOS.
- Other users on the same machine talking to the agent. The socket folder is private, and every connection's user ID is checked.

### Not protected against

- **Malware running as your user while the key is cached and the YubiKey is plugged in.** Such malware could connect to the agent to fetch `pk` and ask the YubiKey for responses. Programming the slot with `--touch` prevents silent use of the key. A short `YKS_CACHE_TTL` or `yks forget` reduces the time the key is exposed.
- **Root or kernel-level compromise.**
- **Clipboard history managers**, which may store the copied secret before `yks` clears it. Exclude `yks` from them or turn them off.
- **Leaking entry names.** File names are visible (see [Storing metadata](#storing-metadata)).
- **Secrets lingering in memory.** Go's garbage collector may keep copies. `yks` clears its buffers where it can, but cannot guarantee complete erasure, and memory is not locked with `mlock`.

---

## Backup and recovery

If you lose the YubiKey's HMAC secret, **every entry becomes permanently unreadable.** Nobody can recover it.

Recommended:

1. Program the slot with **your own secret** (Option B in [YubiKey setup](#yubikey-setup)).
2. Program a **second YubiKey** with the same secret and the same slot, and keep it somewhere safe:
   ```sh
   ykman otp chalresp --touch 2 "$SECRET"
   ```
3. Store the secret offline, for example on paper or in a safe.
4. Back up `~/.ykstore` by any means (git, rsync, cloud). The files are safe to store anywhere.
5. Remember the master password, or store it separately from the YubiKey secret.

To restore on a new machine, build `yks`, copy the store directory and plug in either YubiKey.

If a YubiKey or the HMAC secret backup may have been compromised, program a fresh secret on a new key (or the other slot) and run `yks rekey -d <new serial>` (or `yks rekey -s <other slot>`), preferably with `-p` as well. Then delete the `.bak-*` directory it leaves behind.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ykman otp calculate failed` | The slot is not set up for challenge-response (`ykman otp info`), the key is not connected, or the touch timed out. |
| `unexpected ykman output` | Old `ykman` version, or an extra prompt. Run the test command from [YubiKey setup](#yubikey-setup) manually. |
| `decryption failed after 3 attempts: …` | Wrong password, a different YubiKey or secret, or the file was renamed or moved. Move it back to its original name, decrypt it, then re-encrypt it under the new name. |
| Several YubiKeys connected | Set `YKS_DEVICE=<serial>`. |
| Asked for the password every time | `YKS_CACHE_TTL=0` is set, or the agent could not start: look for a `password cache unavailable` warning on stderr (for example, an insecure socket folder). |
| `insecure agent directory` | The `yks-<uid>` folder has the wrong owner or mode. Check it, then run `rm -r` on it; it is recreated automatically. |
| `no clipboard tool found` | Install `wl-clipboard` (Wayland) or `xclip` (X11). |
| `cannot move old store aside (is … a mount point?)` | `rekey` swaps directories, which is impossible when the store is itself a mount point. Put the store in a subfolder of the mount and point `YKS_DIR` at it. |
| `<entry>: cannot decrypt … (nothing was changed)` during `rekey` | None of the passwords tried, including 3 typed attempts, opened that entry, or the YubiKey is wrong for it. Your store was not modified. |
| `refusing to store an empty secret` | The input to `e` was empty or only whitespace, often because the command feeding the pipe failed. Nothing was written. |
| `git auto-commit skipped: …` | `YKS_GIT=1` is set but the store is not a git repository, git is missing, or the commit failed (for example, commit signing failed). The entry itself was saved. |
| `no store config, run 'yks init'` | The store does not exist yet, or `YKS_DIR` points somewhere else. |
| `unknown flag -x` | A mistyped flag. If `-x` really is the start of an entry name, put `--` before it: `yks d -- -x`. |

---

## Limitations

- **Renaming an entry** requires decrypting and re-encrypting it, because the name is authenticated:
  ```sh
  yks d old/name | yks e new/name && rm ~/.ykstore/old/name.yks
  ```
- **Changing the master password, slot, YubiKey secret or Argon2 settings** means re-encrypting every entry. `yks rekey` does this safely, but it needs one or two YubiKey taps per entry, and the store directory itself must be renamable (it cannot be a mount point).
- **Only HMAC-SHA1 challenge-response is supported**, which is the only challenge-response mode the YubiKey OTP application offers. The response is used only as key material inside HKDF, and HMAC-SHA1 remains secure for that purpose.
- **`c` copies only the first line** unless you add `-a`. Binary entries (such as PDFs) cannot be copied at all; use `yks d name > file`.
- **No built-in version history.** Use git (see [History with git](#history-with-git)). `yks` only commits, with `YKS_GIT=1`; it never pushes or pulls.
- **No built-in password generator or search.** Use existing tools such as `pwgen` and `grep` on `yks ls`.
