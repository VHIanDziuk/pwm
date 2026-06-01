# pwm — Password Manager CLI

## Project Goal

A .NET 8 console application for password management, usable as a CLI tool for quick access to credentials. Claude can read passwords from this tool to authenticate into services on the user's behalf.

## Architecture

- **Language**: C# / .NET 8
- **Storage**: AES-256-GCM encrypted file at `~/.pwm/vault.enc`, unlocked with a master password (PBKDF2-derived key)
- **CLI parsing**: `System.CommandLine`
- **Crypto**: `System.Security.Cryptography` (no external crypto dependencies)
- **Session**: short-lived session token at `~/.pwm/session` to avoid repeated PBKDF2 derivations
- **Config**: optional `~/.pwm/config.toml` for persistent settings

## Source Files

| File | Purpose |
|---|---|
| `Program.cs` | Entry point |
| `Commands.cs` | All CLI command handlers |
| `Vault.cs` | `VaultEntry` record + `VaultStore` (load/save) |
| `Crypto.cs` | AES-256-GCM + PBKDF2 helpers |
| `Session.cs` | Session token read/write/delete |
| `Totp.cs` | RFC 6238 TOTP (HMACSHA1, no external deps) |
| `Config.cs` | `~/.pwm/config.toml` parser |

## Data Model

Each vault entry stores:
- `name` — unique identifier (used as the lookup key)
- `username`
- `password`
- `url`
- `notes`
- `totp_secret` — optional Base32-encoded TOTP secret
- `tags` — optional list of string tags

## Commands

| Command | Description |
|---|---|
| `pwm add <name>` | Add a new entry (prompts for fields); `--totp-secret`, `--tag` |
| `pwm get <name>` | Print entry to stdout (password visible — for scripting/Claude use); `--clip` |
| `pwm list` | List all entry names; `--tag <tag>` to filter |
| `pwm update <name>` | Update fields on an existing entry; `--totp-secret`, `--tag` |
| `pwm delete <name>` | Delete an entry |
| `pwm generate <name>` | Generate and store a random password; `--length`, `--no-symbols` |
| `pwm export` | Dump vault to plaintext JSON; `--out <path>` |
| `pwm import <path>` | Restore from export JSON; `--overwrite` |
| `pwm lock` | Expire the current session token |

## Claude Usage

`pwm get <name>` outputs credentials to stdout so Claude can pipe them into tasks (e.g. logging into a service). The session token means subsequent calls within 15 minutes require no password re-entry. Example:

```bash
pwm get github
# outputs: name, username, password, url, notes (and tags if set)
```

## Security Notes

- Master password is never stored; only the derived key is used in-memory
- Vault file is unreadable without the master password
- `pwm get` intentionally prints to stdout for automation — use in trusted environments only
- Session token at `~/.pwm/session` encrypts the master password with an ephemeral AES-256 key; TTL default 15 min; `pwm lock` clears it
- TOTP secrets are stored inside the encrypted vault; `pwm get` verifies a 6-digit code before printing credentials when a secret is present
