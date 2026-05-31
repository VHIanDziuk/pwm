# pwm Roadmap

---

## v1.0 — Platform Setup

### Windows (x64) setup guide

Walk users through installing `pwm` on Windows x64 from a standing start.

**Prerequisites**

- Download and install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (x64 installer). Verify with `dotnet --version` in a new Command Prompt or PowerShell window.
- Git for Windows (optional, only needed to clone the repo).

**Build and install**

```powershell
cd C:\path\to\pwm
dotnet publish -c Release -r win-x64 --self-contained true -o .\publish
```

Add `C:\path\to\pwm\publish` to your `PATH`:

1. Open **Settings → System → About → Advanced system settings → Environment Variables**.
2. Under **User variables**, select `Path` and click **Edit**.
3. Add a new entry pointing to the `publish` folder.
4. Open a new terminal and run `pwm --version` to confirm.

The vault is created at `%USERPROFILE%\.pwm\vault.enc` (`C:\Users\<you>\.pwm\vault.enc`) on first use.

**Notes**

- `pwm get --clip` uses `clip.exe` on Windows.
- Terminal password masking uses `Console.ReadKey` and works in both Command Prompt and PowerShell. Windows Terminal is recommended for the best experience.
- The session socket path (`~/.pwm/pwmd.sock`) is not supported on Windows in v1.0; the daemon feature is deferred to a later release.

---

### macOS (x64) setup guide

Walk users through installing `pwm` on macOS x64 (Intel Macs) from a standing start.

**Prerequisites**

- Install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) — choose the **macOS x64** installer. Verify with `dotnet --version` in Terminal.
- Xcode Command Line Tools (for `ln`/`sudo`): `xcode-select --install` if not already present.

**Build and install**

```bash
cd /path/to/pwm
dotnet publish -c Release -r osx-x64 --self-contained true -o ./publish
sudo ln -s "$(pwd)/publish/pwm" /usr/local/bin/pwm
```

Verify: `pwm --version`

The vault is created at `~/.pwm/vault.enc` on first use.

**Notes**

- macOS may show a Gatekeeper warning ("cannot be opened because the developer cannot be verified") on first run. To allow it: **System Settings → Privacy & Security → scroll to the blocked app → Allow Anyway**, then re-run.
- Alternatively, clear the quarantine attribute after publishing: `xattr -d com.apple.quarantine ./publish/pwm`
- `pwm get --clip` uses `pbcopy` on macOS.
- For Apple Silicon Macs, use `osx-arm64` as the RID instead of `osx-x64`.

---

## v1.1 — Polish and Correctness

### Session token / timed unlock

Unlock the vault once and write a short-lived session token (encrypted with a random ephemeral key) to `~/.pwm/session`. Subsequent `pwm get` calls within the TTL (default: 15 minutes) skip the PBKDF2 derivation and master password prompt. The session file is deleted on expiry or explicit `pwm lock`. This eliminates the latency and UX friction of repeated PBKDF2 derivations during a working session without storing the master password.

### TOTP second factor on `pwm get`

Store a TOTP secret (Base32-encoded) per entry. When a TOTP secret is present, `pwm get` prompts for the current 6-digit code before printing credentials. Implement HOTP/TOTP entirely with `System.Security.Cryptography.HMACSHA1` — no external dependencies. Add `--totp-secret <base32>` to `pwm add` and `pwm update`. The TOTP secret is stored inside the encrypted vault alongside other fields.

### `pwm export`

Dump the vault to a plaintext JSON file for backup or migration.

```
pwm export [--out <path>]
```

Defaults to `./pwm-export-<timestamp>.json`. Warns explicitly that the output is unencrypted.

### `pwm import`

Restore entries from a `pwm export` JSON file. Skips entries whose names already exist in the vault unless `--overwrite` is passed.

```
pwm import <path> [--overwrite]
```

### `pwm generate <name>`

Generate a cryptographically random password using `RandomNumberGenerator`, store it as a new entry, and print it once to stdout.

```
pwm generate <name> [--length <n>] [--no-symbols]
```

Default length: 24 characters. Character set: uppercase, lowercase, digits, and symbols by default.

---

## v1.2 — Usability

### Tags and categories

Add an optional `Tags` field (list of strings) to `VaultEntry`. Support filtering on `pwm list`:

```
pwm list [--tag <tag>]
```

`pwm add` and `pwm update` accept `--tag <tag>` (repeatable). Tags are stored inside the encrypted vault.

### Clipboard copy mode

Copy the password to the system clipboard instead of printing it, then clear the clipboard after a configurable timeout (default: 30 seconds).

```
pwm get <name> --clip
```

Uses `pbcopy` on macOS, `xclip`/`xdotool` on Linux, `clip` on Windows. The clear is scheduled via a background process that exits after writing an empty string to the clipboard. When `--clip` is used, the password field is omitted from stdout output.

### Vault integrity surface

AES-GCM authentication already detects tampering — the tag verification throws `CryptographicException` on any modification. Improve the user-facing error: distinguish between "wrong master password" and "vault is corrupt or has been tampered with" by catching the exception after a successful key derivation. Print a clear, actionable message in each case.

### Config file

Read `~/.pwm/config.toml` on startup for persistent settings. Supported keys in v1.2:

```toml
session_ttl_seconds = 900        # default 15 minutes
clipboard_clear_seconds = 30     # default 30 seconds
pbkdf2_iterations = 600000       # default, can increase
```

The config file is plaintext and does not affect vault security. PBKDF2 iteration count override applies only to new saves; existing vaults retain their stored iteration count.

---

## v1.3 — Recovery

### Master password recovery

There is no way to recover a forgotten master password without advance preparation — that is the security guarantee of AES-256 encryption. This feature adds two opt-in recovery mechanisms that must be set up before the master password is lost. Neither is enabled by default; users who don't configure one accept that a forgotten master password means permanent data loss.

**Background: why recovery is hard**

The vault is encrypted with a key derived from the master password via PBKDF2. A recovery mechanism must store a second copy of that key (or something equivalent) somewhere. The threat model for recovery is therefore identical to the threat model for the master password itself: wherever the recovery material lives, that is what an attacker must compromise to read your vault. The question is not whether to store a copy of the key, but where and under what conditions.

Two approaches are in scope. Security questions are explicitly excluded (low-entropy answers, often guessable). Cloud or email escrow is excluded (introduces a third-party dependency into an offline tool).

---

**Approach A: OS keychain escrow (recommended)**

At vault creation time (or via `pwm recovery setup`), derive the vault key from the master password, wrap it with a randomly generated 256-bit escrow key, and store the wrapped key in the OS keychain (macOS Keychain, Windows Credential Manager). The escrow key itself is stored separately in the same keychain, protected by OS-level authentication (Touch ID / Face ID / Windows Hello / OS login password).

Recovery flow:

```
pwm recovery restore
# OS prompts for biometric or OS login credential
# vault key is unwrapped from keychain, user sets a new master password
# vault is re-encrypted under the new master password
# old escrow entry is replaced with one derived from the new master password
```

**Threat model:** An attacker who controls your OS account or physical access to your unlocked machine can recover the vault. This is the same attacker who could read a running `pwmd` daemon's memory or observe your screen, so it does not meaningfully weaken the overall security posture of the tool. It is appropriate for single-user personal machines.

**Implementation notes:**

- macOS: `Security.framework` via P/Invoke — `SecItemAdd` / `SecItemCopyMatching` with `kSecClassGenericPassword`. Biometric gate via `LAContext.evaluatePolicy(_:localizedReason:reply:)` (or rely on keychain ACL with `kSecAccessControlBiometryAny`).
- Windows: `Windows.Security.Credentials.PasswordVault` (WinRT) or `CryptProtectData` with the `CRYPTPROTECT_LOCAL_MACHINE` flag absent (user-scoped). Windows Hello gate via `KeyCredentialManager`.
- Linux: `libsecret` (GNOME Keyring / KWallet via the Secret Service D-Bus API). No biometric gate; protected by the user's login session.
- The keychain entry is keyed to the vault file path so multiple vaults get separate escrow entries.
- `pwm recovery disable` removes the keychain entry.

---

**Approach B: Offline recovery code**

At vault creation time (or via `pwm recovery setup --code`), generate a cryptographically random 128-bit recovery code (displayed as 8 groups of 4 hex characters, e.g. `A3F2-91CB-...`). Encrypt the vault key with a key derived from this code (PBKDF2, same parameters as the master password). Store the encrypted key bundle in `~/.pwm/recovery.enc`.

Recovery flow:

```
pwm recovery restore
# prompts for recovery code
# decrypts the key bundle, user sets a new master password
# vault is re-encrypted under the new master password
# recovery.enc is regenerated from the new master password
```

**Threat model:** Anyone who has the recovery code file (`recovery.enc`) and the recovery code itself can decrypt the vault. The code must be stored somewhere safe and separate from the machine — printed and kept offline is the canonical recommendation. Storing it in a cloud note or email defeats the purpose. The UX failure rate for this approach is high in practice; users lose the paper or store it insecurely. This approach is best suited to technically sophisticated users who understand the responsibility.

**Implementation notes:**

- `recovery.enc` format: salt (16 bytes) + nonce (12 bytes) + tag (16 bytes) + encrypted vault key blob. Same structure as `vault.enc` so the same `Crypto` class methods can be reused.
- `pwm recovery setup --code` prints the recovery code once and warns that it cannot be retrieved again. A confirmation prompt requires the user to type it back before saving.
- `pwm recovery disable` deletes `recovery.enc`.

---

**Shared CLI surface**

```
pwm recovery setup [--keychain | --code]   # configure a recovery method
pwm recovery restore                        # recover using whichever method is configured
pwm recovery disable                        # remove recovery material
pwm recovery status                         # show which methods are active
```

If both methods are configured, `pwm recovery restore` presents a menu. `pwm recovery setup` can be run again to add a second method without removing the first.

**What is explicitly not supported:**

- Recovery without prior setup. If no recovery method was configured, the vault cannot be recovered.
- Server-side or email-based key escrow.
- Security questions.
- Recovery from a partial or corrupted vault.

---

## v2.0 — Architecture

### Multiple vaults

Support named vaults selectable at runtime via a global option.

```
pwm --vault work get github
pwm --vault personal list
```

Each vault is a separate `~/.pwm/<name>.enc` file. The default vault remains `vault.enc`. Vault name is validated to contain only alphanumeric characters and hyphens.

### `pwmd` daemon (SSH agent-style)

A lightweight background daemon (`pwmd`) that holds the unlocked vault in memory and serves requests over a Unix domain socket at `~/.pwm/pwmd.sock`. `pwm` detects the running daemon and bypasses PBKDF2 derivation entirely, making `pwm get` near-instant. The daemon exits after a configurable idle timeout, zeroing the in-memory key before exit. This is architecturally equivalent to `ssh-agent`.

```
pwmd start [--ttl <seconds>]
pwmd stop
pwm get <name>          # uses daemon if running, falls back to password prompt
```

### Browser extension bridge

Implement a native messaging host so a browser extension can call `pwm get` and autofill credentials. The native messaging host is a thin wrapper that speaks the Chrome/Firefox native messaging protocol (length-prefixed JSON over stdin/stdout) and delegates to the core vault logic. The extension is out of scope for this repository; the host binary and manifest are in scope.

### Vault format versioning

Prepend a 4-byte magic number and 1-byte version field to `vault.enc`. Version 1 is the current format (salt + nonce + tag + ciphertext). Future versions can change KDF parameters, cipher, or JSON schema while retaining the ability to read older files. On save, always write the latest version. On load, dispatch to the appropriate decoder based on the version byte. This is a breaking change to the file format; v2.0 will include a one-time migration on first load.

---

## v3.0 — GUI Automation

### `pwm auto <name>` — VPN credential auto-fill

A companion Python automation script, invoked via a new `pwm auto <name>` subcommand, that opens the AWS VPN Client, waits for the credential dialog, and fills in username and password retrieved from the vault.

**Scope (v3.0)**

- Target app: AWS VPN Client (Active Directory / username + password auth flow, no SAML browser redirect)
- Target platforms: Windows x64 and macOS x64
- Trigger: manual (`pwm auto <name>`) — no unattended startup automation in this version
- Credential source: calls `pwm get <name>` as a subprocess and parses stdout

**Invocation**

```
pwm auto <vault-entry-name>
```

Example:

```
pwm auto work-vpn
```

The `pwm` .NET CLI resolves the platform at runtime and shells out to the appropriate automation script. The master password is prompted interactively as usual; credentials are never written to disk or environment variables.

**Windows implementation**

Uses `pywinauto` (Windows UI Automation API) to locate the AWS VPN Client window by process name (`AWSVPN.exe`), find the username and password edit controls by automation ID or control class, fill them, and click the Connect button. Element-based automation survives DPI scaling and theme changes. Explicit waits (polling every 500 ms) replace fixed sleeps to handle app startup latency.

**macOS implementation**

Uses `open -a "AWS VPN Client"` to launch the app, then `pywinauto`'s `Application` backend or PyAutoGUI coordinate clicks to target the credential fields. Window readiness is detected by polling for the dialog title. Because macOS accessibility automation requires user consent, setup includes a one-time step to grant Accessibility permission to the terminal or script runner in System Settings → Privacy & Security → Accessibility.

**Packaging**

Each platform's script is compiled to a standalone executable via PyInstaller (`pwm-auto.exe` on Windows, `pwm-auto` on macOS) and distributed alongside the main `pwm` binary. Users do not need a Python installation.

**Security notes**

- Credentials are held in the Python process's memory only for the duration of the automation run and are not written anywhere else.
- The script verifies the VPN app window is focused before typing, reducing the risk of credentials being sent to a wrong window.
- This feature is designed for use on personal, trusted machines. It is not suitable for shared or monitored environments.
- SAML/federated auth (browser-based login) is out of scope; if the AWS VPN endpoint is reconfigured for SAML, this feature will not work and will exit with a clear error.

**Known limitations**

- AWS VPN Client UI changes (control IDs, layout) may break automation between app versions; the script will require updates when the client is upgraded.
- MFA (TOTP second factor) is not supported in v3.0. If MFA is added to the VPN endpoint, the script will pause at the MFA prompt and time out. TOTP integration (using the `pwm` v1.1 TOTP field) is a candidate for v3.1.
- Unattended startup automation (running at login without user interaction) requires either a cached master password or a session token from the v1.1 session feature, and is deferred to v3.1.
