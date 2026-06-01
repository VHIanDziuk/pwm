# pwm Usage Guide

## Overview

`pwm` is a command-line password manager for .NET 8. Credentials are stored in a single AES-256-GCM encrypted file at `~/.pwm/vault.enc`, unlocked at runtime with a master password. There are no external crypto dependencies — all cryptographic operations use `System.Security.Cryptography`.

---

## Installation

### Option 1: Publish and symlink (recommended)

```bash
cd /path/to/pwm
dotnet publish -c Release -r osx-arm64 --self-contained true -o ./publish
# Replace osx-arm64 with your RID (linux-x64, osx-x64, win-x64, etc.)
sudo ln -s "$(pwd)/publish/pwm" /usr/local/bin/pwm
```

After this, `pwm` is available anywhere in your shell.

### Option 2: Run from source

```bash
dotnet run --project /path/to/pwm -- <command> [args]
```

---

## First Use

No initialization step is required. The vault directory (`~/.pwm/`) and vault file (`vault.enc`) are created automatically the first time you run `pwm add`. Choose your master password at that prompt — there is no built-in recovery mechanism if it is lost.

---

## Session Tokens

After the first successful unlock, `pwm` writes a short-lived session token to `~/.pwm/session`. Subsequent commands within the TTL (default: 15 minutes) skip the PBKDF2 derivation and master password prompt entirely, making them near-instant.

```bash
pwm get github        # prompts for master password, writes session token
pwm get github        # no prompt — uses session
pwm list              # no prompt — uses session
pwm lock              # deletes the session token
pwm get github        # prompts again
```

The session TTL is configurable via `~/.pwm/config.toml` (see [Config File](#config-file)).

---

## Commands

### `pwm add <name>`

Add a new entry. Prompts for master password (or uses session), then for each field. Name matching is case-insensitive; a duplicate name is rejected.

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

Retrieve a single entry and print all fields to stdout. Password is printed in plaintext by default. This is intentional for scripting and automation.

If a TOTP secret is stored on the entry, you will be prompted for the current 6-digit code before credentials are shown.

**Options**

| Option | Description |
|---|---|
| `--clip` | Copy password to clipboard instead of printing it; clears after 30 s |

**Example**

```
$ pwm get github
Name:     github
Username: iandziuk
Password: hunter2
URL:      https://github.com
Notes:    personal account
Tags:     work, git
```

**Clipboard mode**

```
$ pwm get github --clip
Name:     github
Username: iandziuk
URL:      https://github.com
Notes:    personal account
Tags:     work, git
Password copied to clipboard (cleared in 30s)
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

Generate a cryptographically random password, store it as a new entry, and print it once to stdout.

**Options**

| Option | Default | Description |
|---|---|---|
| `--length <n>` | 24 | Password length |
| `--no-symbols` | off | Exclude symbols; use only A-Z, a-z, 0-9 |

**Example**

```
$ pwm generate db-prod --length 32
Master password: ********
Username (optional): 
URL (optional): 
Notes (optional): 
Generated password: kR7#mPqW2$vLxN9@cJdF4!hYbT8&eZsA
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

Expire the current session token immediately. The next command will prompt for the master password again.

```
$ pwm lock
Session locked.
```

---

## Config File

Create `~/.pwm/config.toml` to override defaults. The file is optional and plaintext.

```toml
session_ttl_seconds = 900        # default: 900 (15 minutes)
clipboard_clear_seconds = 30     # default: 30
pbkdf2_iterations = 600000       # default: 600000 (applies to new saves only)
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

**What is protected:** the vault file is unreadable without the master password. AES-GCM's authentication tag detects any tampering with the ciphertext. If the vault is corrupt or tampered with, `pwm` prints a distinct error message rather than a generic wrong-password error.

**What is not protected:**

- The master password itself — it is never stored, but can be captured by an observer with terminal or memory access.
- `pwm get` output — credentials are printed to stdout in plaintext. Stdout may be captured by shell history, terminal scrollback, logging, or any process that reads the pipe. Use `--clip` to avoid printing the password.
- The vault file at rest is protected only as well as the filesystem permissions on `~/.pwm/`. Ensure that directory is not world-readable.
- The session token at `~/.pwm/session` contains the master password encrypted with an ephemeral key stored in the same file. It is protected by filesystem permissions only; run `pwm lock` when leaving a shared machine.

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

`pwm get <name>` writes all fields to stdout, making it straightforward for Claude to read credentials and use them in automated tasks. The session token means repeated calls during a working session require no re-prompting.

**Example: Claude reads credentials to authenticate into a service**

```bash
pwm get github
# Claude receives:
# Name:     github
# Username: iandziuk
# Password: hunter2
# URL:      https://github.com
# Notes:    personal account
```

Claude can invoke `pwm get <name>` as a shell command and parse the output to extract the username, password, and URL before performing a login or API call on the user's behalf.

Use this only in trusted environments where stdout is not being captured by unintended processes.
