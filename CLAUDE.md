# pwm — Password Manager CLI

## Project Goal

A .NET 8 console application for password management, usable as a CLI tool for quick access to credentials. Claude can read passwords from this tool to authenticate into services on the user's behalf.

## Architecture

- **Language**: C# / .NET 8
- **Storage**: AES-256 encrypted file at `~/.pwm/vault.enc`, unlocked with a master password (PBKDF2-derived key)
- **CLI parsing**: `System.CommandLine`
- **Crypto**: `System.Security.Cryptography` (no external crypto dependencies)

## Data Model

Each vault entry stores:
- `name` — unique identifier (used as the lookup key)
- `username`
- `password`
- `url`
- `notes`

## Commands

| Command | Description |
|---|---|
| `pwm add <name>` | Add a new entry (prompts for fields) |
| `pwm get <name>` | Print entry to stdout (password visible — for scripting/Claude use) |
| `pwm list` | List all entry names |
| `pwm update <name>` | Update fields on an existing entry |
| `pwm delete <name>` | Delete an entry |

## Claude Usage

`pwm get <name>` outputs credentials to stdout so Claude can pipe them into tasks (e.g. logging into a service). Example:

```bash
pwm get github
# outputs: name, username, password, url
```

## Security Notes

- Master password is never stored; only the derived key is used in-memory
- Vault file is unreadable without the master password
- `pwm get` intentionally prints to stdout for automation — use in trusted environments only
