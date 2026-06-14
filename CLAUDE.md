# pwm — Password Manager CLI

## Project Goal

A .NET 8 console application for password management, usable as a CLI tool for quick access to credentials.

## Architecture

- **Language**: C# / .NET 8
- **Storage**: AES-256-GCM encrypted file at `~/.pwm/vault.enc`, unlocked with a master password (PBKDF2-derived key)
- **CLI parsing**: `System.CommandLine`
- **Crypto**: `System.Security.Cryptography` (no external crypto dependencies)
- **Session**: short-lived session token at `~/.pwm/session` to avoid repeated PBKDF2 derivations
- **Daemon**: optional `pwmd` background process holds the vault in memory over a Unix domain socket at `~/.pwm/pwmd.sock`; commands route through it automatically when running
- **Config**: optional `~/.pwm/config.toml` for persistent settings

## Source Files

| File | Purpose |
|---|---|
| `Program.cs` | Entry point; intercepts `__daemon` flag to run daemon loop |
| `Commands.cs` | All CLI command handlers |
| `Vault.cs` | `VaultEntry` record + `VaultStore` (load/save) |
| `Crypto.cs` | AES-256-GCM + PBKDF2 helpers |
| `Session.cs` | Session token read/write/delete |
| `Totp.cs` | RFC 6238 TOTP (HMACSHA1, no external deps) |
| `Config.cs` | `~/.pwm/config.toml` parser |
| `Daemon.cs` | Unix socket server — holds vault in memory, serves requests |
| `DaemonClient.cs` | Client-side socket helpers used by command handlers |
| `DaemonProtocol.cs` | Shared newline-delimited JSON request/response types |

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
| `pwm generate <name>` | Generate and store a random password; `--length`, `--no-symbols`, `--clip` |
| `pwm export` | Dump vault to plaintext JSON; `--out <path>` |
| `pwm import <path>` | Restore from export JSON; `--overwrite` |
| `pwm lock` | Expire the current session token |
| `pwm daemon start` | Fork the background daemon |
| `pwm daemon stop` | Stop the daemon cleanly |
| `pwm daemon status` | Show running/locked/unlocked state |

## Claude Usage

`pwm get <name> --show` outputs credentials to stdout so Claude can pipe them into tasks (e.g. logging into a service). The `--show` flag is required to print the password; without it the password is copied to the clipboard only. The session token and daemon mean subsequent calls within a working session require no password re-entry. Example:

```bash
pwm get github --show
# outputs: name, username, password, url, notes (and tags if set)
```

If the daemon is running and the vault is unlocked, `pwm get` is near-instant with no prompt.

## Security Notes

- Master password is never stored; only the derived key is used in-memory
- Vault file is unreadable without the master password
- `pwm get` copies the password to the clipboard by default; use `--show` to print to stdout for automation — use only in trusted environments
- Session token at `~/.pwm/session` encrypts the master password with an ephemeral AES-256 key; TTL default 15 min; `pwm lock` clears it
- TOTP secrets are stored inside the encrypted vault; `pwm get` verifies a 6-digit code before printing credentials when a secret is present
- Daemon holds the vault and master password in process memory; `pwm daemon stop` zeroes all key material before exit
