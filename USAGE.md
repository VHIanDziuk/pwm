# pwm Usage Guide

## Overview

`pwm` is a command-line password manager for .NET 8. Credentials are stored in a single AES-256-GCM encrypted file at `~/.pwm/vault.enc`, unlocked at runtime with a master password. There are no external crypto dependencies — all cryptographic operations use `System.Security.Cryptography`. The tool is intentionally simple: five commands, one vault, one password.

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

No initialization step is required. The vault directory (`~/.pwm/`) and vault file (`vault.enc`) are created automatically the first time you run `pwm add`. Choose your master password at that prompt — there is no recovery mechanism if it is lost.

---

## Commands

### `pwm add <name>`

Add a new entry. Prompts for master password, then for each field. Name matching is case-insensitive; a duplicate name is rejected.

**Syntax**

```
pwm add <name>
```

**Example session**

```
$ pwm add github
Master password: ********
Username: iandziuk
Password: ********
URL: https://github.com
Notes: personal account
```

---

### `pwm get <name>`

Retrieve a single entry and print all fields to stdout. Password is printed in plaintext. This is intentional for scripting and automation.

**Syntax**

```
pwm get <name>
```

**Example session**

```
$ pwm get github
Master password: ********
Name:     github
Username: iandziuk
Password: hunter2
URL:      https://github.com
Notes:    personal account
```

---

### `pwm list`

List all entry names in alphabetical order.

**Syntax**

```
pwm list
```

**Example session**

```
$ pwm list
Master password: ********
github
mailserver
work-vpn
```

---

### `pwm update <name>`

Update fields on an existing entry. Each prompt shows the current value in brackets; press Enter to keep it. The entry name cannot be changed.

**Syntax**

```
pwm update <name>
```

**Example session**

```
$ pwm update github
Master password: ********
Username [iandziuk]: 
Password [leave blank to keep]: ********
URL [https://github.com]: 
Notes [personal account]: personal + work account
```

---

### `pwm delete <name>`

Delete an entry after confirmation. Responds only to `y` (case-insensitive); anything else aborts.

**Syntax**

```
pwm delete <name>
```

**Example session**

```
$ pwm delete work-vpn
Master password: ********
Delete 'work-vpn'? [y/N] y
```

---

## Security Model

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-SHA256, 600,000 iterations |
| Salt | 16 bytes, random per save |
| Nonce | 12 bytes, random per save |
| Auth tag | 16 bytes (GCM built-in) |
| Vault location | `~/.pwm/vault.enc` |

**What is protected:** the vault file is unreadable without the master password. AES-GCM's authentication tag ensures any tampering with the ciphertext is detected on load.

**What is not protected:**

- The master password itself — it is never stored, but if an attacker observes your terminal or has access to your process memory, it can be captured.
- `pwm get` output — credentials are printed to stdout in plaintext. Stdout may be captured by shell history, terminal scrollback, logging, or any process that reads the pipe.
- The vault file at rest is protected only as well as the filesystem permissions on `~/.pwm/vault.enc`. Ensure that directory is not world-readable.

The derived key is zeroed from memory immediately after each encrypt/decrypt operation via `CryptographicOperations.ZeroMemory`.

---

## Portability

The vault is a single self-contained binary file. To use it across devices:

1. Sync `~/.pwm/vault.enc` using any method (iCloud Drive, Dropbox, rsync, etc.).
2. Ensure the file path resolves to `~/.pwm/vault.enc` on each machine, or symlink accordingly.
3. The same master password decrypts the vault on any platform where `pwm` is installed.

The vault format is platform-independent — it contains no OS-specific data.

---

## Claude Integration

`pwm get` writes all fields to stdout, making it straightforward for Claude to read credentials and use them in automated tasks.

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

Claude can invoke `pwm get <name>` as a shell command and parse the output to extract username, password, and URL before performing a login or API call on the user's behalf. Because the output is plaintext on stdout, it works naturally in any scripting or agent context — no special parsing or decryption is required.

Use this only in trusted environments where stdout is not being captured by unintended processes.
