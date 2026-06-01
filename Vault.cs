using System.Text.Json;

namespace Pwm;

/// <summary>
/// Represents a single credential entry stored in the vault.
/// </summary>
/// <remarks>
/// <see cref="TotpSecret"/> is a Base32-encoded TOTP shared secret (RFC 6238).
/// When present, <c>pwm get</c> will require the user to supply a valid 6-digit
/// code before revealing credentials — providing a second factor even for
/// automated callers that already possess the vault master password.
/// </remarks>
record VaultEntry(
    string        Name,
    string        Username,
    string        Password,
    string        Url,
    string        Notes,
    string?       TotpSecret = null,
    List<string>? Tags       = null);

/// <summary>
/// Handles persistence of the encrypted vault file at <c>~/.pwm/vault.enc</c>.
/// </summary>
static class VaultStore
{
    private static readonly string VaultDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pwm");

    private static readonly string VaultPath = Path.Combine(VaultDir, "vault.enc");

    /// <summary>
    /// Loads and decrypts the vault, returning all stored entries.
    /// </summary>
    /// <param name="masterPassword">
    /// The user's master password, used to derive the AES-256-GCM key via PBKDF2.
    /// </param>
    /// <returns>
    /// The list of vault entries, or an empty list when the vault file does not yet exist.
    /// </returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when the password is wrong or the file has been tampered with —
    /// AES-GCM authentication ensures the two failure modes are indistinguishable
    /// to callers (by design).
    /// </exception>
    public static List<VaultEntry> Load(string masterPassword)
    {
        Directory.CreateDirectory(VaultDir);

        if (!File.Exists(VaultPath))
            return [];

        var blob = File.ReadAllBytes(VaultPath);
        var json = Crypto.Decrypt(blob, masterPassword);
        return JsonSerializer.Deserialize<List<VaultEntry>>(json)!;
    }

    /// <summary>
    /// Serializes and encrypts <paramref name="entries"/>, then atomically replaces
    /// the vault file.
    /// </summary>
    /// <param name="entries">The full list of entries to persist.</param>
    /// <param name="masterPassword">Master password used to re-derive the encryption key.</param>
    /// <param name="iterations">
    /// PBKDF2 iteration count. Defaults to 600,000 (NIST SP 800-132 recommendation for
    /// HMAC-SHA-256 as of 2023). Configurable via <c>~/.pwm/config.toml</c> to allow
    /// future strengthening without breaking existing vaults.
    /// </param>
    /// <remarks>
    /// The write is performed via a temporary file followed by an atomic
    /// <see cref="File.Move"/> so a crash mid-write cannot produce a truncated vault.
    /// A fresh salt and nonce are generated on every save, so two identical plaintexts
    /// will produce different ciphertexts.
    /// </remarks>
    public static void Save(List<VaultEntry> entries, string masterPassword, int iterations = 600_000)
    {
        Directory.CreateDirectory(VaultDir);

        var json = JsonSerializer.Serialize(entries);
        var blob = Crypto.Encrypt(json, masterPassword, iterations);

        var tmp = VaultPath + ".tmp";
        File.WriteAllBytes(tmp, blob);
        File.Move(tmp, VaultPath, overwrite: true);
    }
}
