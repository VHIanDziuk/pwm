# pwm Usage Guide

## Overview

`pwm` is a command-line password manager for .NET 8. Credentials are stored in a single AES-256-GCM encrypted file at `~/.pwm/vault.enc`, unlocked at runtime with a master password. There are no external crypto dependencies — all cryptographic operations use `System.Security.Cryptography`.

---

## Installation

### Option 1: Publish and symlink (recommended)

```bash
cd /path/to/pwm

# Pick the RID that matches your machine:
#   osx-x64   — macOS on Intel
#   osx-arm64 — macOS on Apple Silicon (M1/M2/M3)
#   linux-x64 — Linux x86-64
dotnet publish -c Release -r osx-x64 --self-contained true -o ./publish

# Create ~/.local/bin if it doesn't exist, then symlink (no sudo required)
mkdir -p ~/.local/bin
ln -s "$(pwd)/publish/pwm" ~/.local/bin/pwm
```

Add `~/.local/bin` to your PATH if it isn't already (add this to `~/.zshrc` or `~/.bashrc`):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell:

```bash
source ~/.zshrc   # or source ~/.bashrc
```

After this, `pwm` is available anywhere in your shell.

> **Tip:** If you ever rebuild `publish/` (e.g. to switch RID), the symlink keeps working — no need to recreate it.

### Option 2: Run from source

```bash
dotnet run --project /path/to/pwm -- <command> [args]
```

---

## Quick-Start Tutorial

This section walks through the most common workflows end-to-end.

### 1. Add your first entry

```
$ pwm add github
Master password: ********
Username: iandziuk
Password: ********
URL: https://github.com
Notes: personal account
```

The vault file `~/.pwm/vault.enc` is created on first use. Your master password is never stored — choose it carefully, there is no built-in recovery.

### 2. Retrieve credentials

```
$ pwm get github
Master password: ********
Name:     github
Username: iandziuk
URL:      https://github.com
Notes:    personal account
Password copied to clipboard (cleared in 30s)
```

The password is copied to your clipboard and never printed. Use `--show` to print it instead (for scripts or Claude automation).

After this first unlock, a session token is cached for 15 minutes so you won't be prompted again.

### 3. Use the daemon for a working session

Start the daemon once and every subsequent command is instant:

```
$ pwm daemon start
pwmd started.

$ pwm get github
Master password: ********
Name:     github
Username: iandziuk
Password: hunter2
URL:      https://github.com
Notes:    personal account

$ pwm get work-vpn
Name:     work-vpn
...
$ pwm list
github
work-vpn

$ pwm daemon stop
pwmd stopped.
```

After the first unlock the vault lives in the daemon's memory — no PBKDF2 on subsequent calls.

### 4. Generate a new credential

```
$ pwm generate myservice --clip
Master password: ********
Username (optional): myuser
URL (optional): https://myservice.example.com
Notes (optional):
Password generated and copied to clipboard (cleared in 30s)
```

Open the browser, paste from clipboard. The password never appears on screen.

### 5. Organise with tags

```
$ pwm add work-jira --tag work --tag jira
$ pwm add personal-email --tag personal

$ pwm list --tag work
work-jira

$ pwm list --tag personal
personal-email
```

### 6. Rotate a password

```
$ pwm update github
Master password: ********
Username [iandziuk]:
Password [leave blank to keep]: ********
URL [https://github.com]:
Notes [personal account]:
```

Press Enter to keep any field unchanged.

### 7. Add a TOTP second factor

```
$ pwm update github --totp-secret JBSWY3DPEHPK3PXP

$ pwm get github
Master password: ********
TOTP code: 482916
Name:     github
...
```

### 8. Export and import

```
$ pwm export --out backup.json
WARNING: This file is unencrypted. Store it securely.
backup.json

$ pwm import backup.json --overwrite
Imported 5 entries, skipped 0.
```

---

## Session Tokens

After the first successful unlock, `pwm` writes a short-lived session token to `~/.pwm/session`. Subsequent commands within the TTL (default: 15 minutes) skip the PBKDF2 derivation and master password prompt entirely.

```bash
pwm get github        # prompts for master password, writes session token
pwm get github        # no prompt — uses session
pwm list              # no prompt — uses session
pwm lock              # deletes the session token
pwm get github        # prompts again
```

The session TTL is configurable via `~/.pwm/config.toml` (see [Config File](#config-file)).

The session token is separate from the daemon. With no daemon running, the token provides prompt-free operation for 15 minutes. With the daemon running, the daemon holds the vault in memory indefinitely (up to its idle timeout) and the session token is also refreshed on each unlock.

---

## Daemon

The `pwmd` daemon holds the decrypted vault in memory over a Unix domain socket (`~/.pwm/pwmd.sock`). While the daemon is running and the vault is unlocked, `pwm` commands require no password prompt and no PBKDF2 derivation — they are near-instant.

### Starting and stopping

```bash
pwm daemon start     # fork daemon in background, wait for socket to be ready
pwm daemon status    # print running state and whether vault is unlocked
pwm daemon stop      # send stop command, clean up socket
```

### How it works

1. `pwm daemon start` re-launches the `pwm` binary in the background with an internal flag. The parent polls the socket for up to 2 seconds then exits.
2. The first `pwm` command after `daemon start` finds the socket, sees the vault is locked, prompts once for the master password, and sends an "unlock" request to the daemon.
3. Every subsequent command skips the password prompt entirely and communicates with the daemon over the socket.
4. The daemon auto-locks (zeroes in-memory key material) after `daemon_idle_seconds` (default: 15 minutes) of inactivity. It does not exit — it stays alive in a locked state until the next unlock or a stop command.
5. `pwm daemon stop` sends a stop command; the daemon zeroes all key material and removes the socket file before exiting.

### When the daemon is not running

All commands fall back transparently to direct vault access (PBKDF2 decryption + session token). You never need to run the daemon — it is purely an optimisation.

### Config

```toml
daemon_idle_seconds = 900    # default: 900 (15 minutes)
```

### Platform notes

Unix domain sockets are supported on macOS, Linux, and Windows 10 build 17063+. On all platforms the socket file is created with owner-only permissions (mode 600 on Unix; best-effort on Windows).

---

## Commands

### `pwm add <name>`

Add a new entry. Prompts for master password (or uses session/daemon), then for each field. Name matching is case-insensitive; a duplicate name is rejected.

**Options**

| Option | Description |
|---|---|
| `--totp-secret <base32>` | Store a TOTP secret for this entry |
| `--tag <tag>` | Assign a tag (repeatable: `--tag work --tag git`) |

**Example**

```
$ pwm add github --tag work --tag git
Master password: ********
Username: iandziuk
Password: ********
URL: https://github.com
Notes: personal account
```

---

### `pwm get <name>`

Retrieve a single entry. By default the password is copied to the clipboard and cleared after 30 seconds — it is never printed. Use `--show` to print it to stdout instead (for scripting and automation).

If a TOTP secret is stored on the entry, you will be prompted for the current 6-digit code before credentials are shown.

**Options**

| Option | Description |
|---|---|
| `--show` | Print password to stdout instead of copying to clipboard |

**Example (default — clipboard)**

```
$ pwm get github
Name:     github
Username: iandziuk
URL:      https://github.com
Notes:    personal account
Tags:     work, git
Password copied to clipboard (cleared in 30s)
```

**Print mode**

```
$ pwm get github --show
Name:     github
Username: iandziuk
Password: hunter2
URL:      https://github.com
Notes:    personal account
Tags:     work, git
```

---

### `pwm list`

List all entry names in alphabetical order. Optionally filter by tag.

**Options**

| Option | Description |
|---|---|
| `--tag <tag>` | Only show entries that have this tag |

**Example**

```
$ pwm list --tag work
github
work-jira
work-vpn
```

---

### `pwm update <name>`

Update fields on an existing entry. Each prompt shows the current value in brackets; press Enter to keep it. The entry name cannot be changed.

**Options**

| Option | Description |
|---|---|
| `--totp-secret <base32>` | Set a new TOTP secret (pass empty string to clear) |
| `--tag <tag>` | Replace all existing tags (repeatable); omit to keep existing tags |

**Example**

```
$ pwm update github --tag work --tag vcs
Master password: ********
Username [iandziuk]:
Password [leave blank to keep]:
URL [https://github.com]:
Notes [personal account]:
```

---

### `pwm delete <name>`

Delete an entry after confirmation. Responds only to `y` (case-insensitive); anything else aborts.

**Example**

```
$ pwm delete work-vpn
Master password: ********
Delete 'work-vpn'? [y/N] y
```

---

### `pwm generate <name>`

Generate a cryptographically random password, store it as a new entry, and print it once to stdout. Use `--clip` to copy it to the clipboard instead of printing.

**Options**

| Option | Default | Description |
|---|---|---|
| `--length <n>` | 24 | Password length |
| `--no-symbols` | off | Exclude symbols; use only A-Z, a-z, 0-9 |
| `--clip` | off | Copy to clipboard instead of printing; clears after 30 s |

**Example — print**

```
$ pwm generate db-prod --length 32
Master password: ********
Username (optional):
URL (optional):
Notes (optional):
Generated password: kR7#mPqW2$vLxN9@cJdF4!hYbT8&eZsA
```

**Example — clipboard (screen-safe)**

```
$ pwm generate myservice --clip
Master password: ********
Username (optional): myuser
URL (optional):
Notes (optional):
Password generated and copied to clipboard (cleared in 30s)
```

---

### `pwm export`

Dump all vault entries to a plaintext JSON file. The output is **unencrypted** — a warning is printed.

**Options**

| Option | Default | Description |
|---|---|---|
| `--out <path>` | `./pwm-export-<timestamp>.json` | Output file path |

**Example**

```
$ pwm export --out backup.json
Master password: ********
WARNING: This file is unencrypted. Store it securely.
backup.json
```

---

### `pwm import <path>`

Restore entries from a `pwm export` JSON file. Entries whose names already exist in the vault are skipped unless `--overwrite` is passed.

**Options**

| Option | Description |
|---|---|
| `--overwrite` | Replace existing entries with imported ones |

**Example**

```
$ pwm import backup.json
Master password: ********
Skipped: github
Imported 3 entries, skipped 1.
```

---

### `pwm lock`

Expire the current session token immediately. The next command will prompt for the master password again. Does not stop the daemon — use `pwm daemon stop` for that.

```
$ pwm lock
Session locked.
```

---

### `pwm daemon <subcommand>`

Manage the background daemon process.

| Subcommand | Description |
|---|---|
| `pwm daemon start` | Fork the daemon in the background |
| `pwm daemon stop` | Stop the running daemon cleanly |
| `pwm daemon status` | Show whether the daemon is running and the vault is unlocked |

See the [Daemon](#daemon) section above for full details.

---

## Config File

Create `~/.pwm/config.toml` to override defaults. The file is optional and plaintext.

```toml
session_ttl_seconds = 900        # default: 900 (15 minutes)
clipboard_clear_seconds = 30     # default: 30
pbkdf2_iterations = 600000       # default: 600000 (applies to new saves only)
daemon_idle_seconds = 900        # default: 900 (15 minutes)
```

Lines beginning with `#` are comments. Unknown keys are silently ignored. The PBKDF2 iteration count override applies only when the vault is re-saved; existing vaults retain their stored iteration count.

---

## TOTP Second Factor

If an entry has a TOTP secret, `pwm get` will prompt for the current 6-digit code (from your authenticator app) before printing credentials.

**Add a TOTP secret when creating an entry:**

```
$ pwm add github --totp-secret JBSWY3DPEHPK3PXP
```

**Add or update a TOTP secret on an existing entry:**

```
$ pwm update github --totp-secret JBSWY3DPEHPK3PXP
```

**Remove a TOTP secret:**

```
$ pwm update github --totp-secret ""
```

---

## Security Model

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-SHA256, 600,000 iterations (configurable) |
| Salt | 16 bytes, random per save |
| Nonce | 12 bytes, random per save |
| Auth tag | 16 bytes (GCM built-in) |
| Vault location | `~/.pwm/vault.enc` |
| Session token | `~/.pwm/session` — ephemeral AES-256 key, TTL-bound |
| Daemon socket | `~/.pwm/pwmd.sock` — Unix domain socket, owner-only permissions |

**What is protected:** the vault file is unreadable without the master password. AES-GCM's authentication tag detects any tampering with the ciphertext. If the vault is corrupt or tampered with, `pwm` prints a distinct error message rather than a generic wrong-password error.

**What is not protected:**

- The master password itself — it is never stored, but can be captured by an observer with terminal or memory access.
- `pwm get` output — credentials are printed to stdout in plaintext. Stdout may be captured by shell history, terminal scrollback, logging, or any process that reads the pipe. Use `--clip` to avoid printing the password.
- The vault file at rest is protected only as well as the filesystem permissions on `~/.pwm/`. Ensure that directory is not world-readable.
- The session token at `~/.pwm/session` contains the master password encrypted with an ephemeral key stored in the same file. It is protected by filesystem permissions only; run `pwm lock` when leaving a shared machine.
- The daemon holds the decrypted vault and master password in process memory. An attacker with the ability to read process memory on the local machine can recover credentials while the daemon is running. Stop the daemon with `pwm daemon stop` when leaving a shared machine.

The derived key is zeroed from memory immediately after each encrypt/decrypt operation via `CryptographicOperations.ZeroMemory`.

---

## Portability

The vault is a single self-contained binary file. To use it across devices:

1. Sync `~/.pwm/vault.enc` using any method (iCloud Drive, Dropbox, rsync, etc.).
2. Ensure the file path resolves to `~/.pwm/vault.enc` on each machine.
3. The same master password decrypts the vault on any platform where `pwm` is installed.

The vault format is platform-independent.

---

## Claude Integration

`pwm get <name>` writes all fields to stdout, making it straightforward for Claude to read credentials and use them in automated tasks. The session token and daemon mean repeated calls during a working session require no re-prompting.

**Example: Claude reads credentials to authenticate into a service**

```bash
pwm get github --show
# Claude receives:
# Name:     github
# Username: iandziuk
# Password: hunter2
# URL:      https://github.com
# Notes:    personal account
```

Claude can invoke `pwm get <name> --show` as a shell command and parse the output to extract the username, password, and URL before performing a login or API call on the user's behalf.

Use this only in trusted environments where stdout is not being captured by unintended processes.
