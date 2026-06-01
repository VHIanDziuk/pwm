using System.Security.Cryptography;
using System.Text;

namespace Pwm;

/// <summary>
/// Manages the short-lived session token that caches the master password so
/// subsequent commands within the TTL window do not require PBKDF2 re-derivation.
/// </summary>
/// <remarks>
/// <para>
/// The master password is never stored in plaintext. Instead it is encrypted with a
/// per-session ephemeral AES-256-GCM key that is stored alongside the ciphertext in
/// the session file. This means:
/// <list type="bullet">
///   <item>An attacker who can read <c>~/.pwm/session</c> can recover the master password —
///         the file is created with mode 600 (owner read/write only) to mitigate this.</item>
///   <item>The design trades the cost of PBKDF2 (slow by design) for an ephemeral AES key
///         (fast), so 15-minute interactive sessions feel responsive.</item>
///   <item>The ephemeral key provides no cryptographic hardening against an attacker with
///         filesystem read access; its purpose is to avoid storing the password in plaintext
///         and to make accidental exposure (e.g. log files) less dangerous.</item>
/// </list>
/// </para>
/// <para>
/// Session file layout:
/// <code>
///   expiry         8 bytes  — big-endian int64 Unix seconds
///   nonce         12 bytes  — AES-GCM nonce
///   tag           16 bytes  — AES-GCM authentication tag
///   ciphertext    variable  — UTF-8 master password, AES-GCM encrypted
///   ephemeral_key 32 bytes  — raw AES-256 key (appended at end)
/// </code>
/// </para>
/// </remarks>
static class SessionStore
{
    private static readonly string SessionPath =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".pwm", "session");

    // Session file layout:
    //   expiry         8 bytes  — big-endian int64 Unix seconds
    //   nonce         12 bytes  — AES-GCM nonce
    //   tag           16 bytes  — AES-GCM authentication tag
    //   ciphertext    variable  — UTF-8 master password, AES-GCM encrypted
    //   ephemeral_key 32 bytes  — raw AES-256 key (appended at end)

    private const int ExpirySize       = 8;
    private const int NonceSize        = 12;
    private const int TagSize          = 16;
    private const int EphemeralKeySize = 32;
    private const int MinFileSize      = ExpirySize + NonceSize + TagSize + EphemeralKeySize;

    /// <summary>
    /// Encrypts <paramref name="masterPassword"/> with a fresh ephemeral key and writes
    /// the session file, silently ignoring any I/O error.
    /// </summary>
    /// <param name="masterPassword">The plaintext master password to cache.</param>
    /// <param name="ttlSeconds">
    /// How many seconds the session remains valid. Defaults to 900 (15 minutes).
    /// Configurable via <c>~/.pwm/config.toml</c> (<c>session_ttl_seconds</c>).
    /// </param>
    /// <remarks>
    /// All sensitive byte arrays (plaintext password, ephemeral key, assembled blob) are
    /// zeroed with <see cref="CryptographicOperations.ZeroMemory"/> before the method returns.
    /// The method swallows all exceptions so a non-writeable filesystem never prevents a
    /// command from succeeding — it just means the next command will prompt again.
    /// </remarks>
    public static void TrySave(string masterPassword, int ttlSeconds = 900)
    {
        try
        {
            var dir = Path.GetDirectoryName(SessionPath)!;
            Directory.CreateDirectory(dir);

            long expiry = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ttlSeconds;

            var ephemeralKey = RandomNumberGenerator.GetBytes(EphemeralKeySize);
            var nonce        = RandomNumberGenerator.GetBytes(NonceSize);
            var plaintext    = Encoding.UTF8.GetBytes(masterPassword);
            var ciphertext   = new byte[plaintext.Length];
            var tag          = new byte[TagSize];

            using (var aes = new AesGcm(ephemeralKey, TagSize))
                aes.Encrypt(nonce, plaintext, ciphertext, tag);

            CryptographicOperations.ZeroMemory(plaintext);

            var blob = new byte[ExpirySize + NonceSize + TagSize + ciphertext.Length + EphemeralKeySize];
            int offset = 0;

            blob[offset++] = (byte)(expiry >> 56);
            blob[offset++] = (byte)(expiry >> 48);
            blob[offset++] = (byte)(expiry >> 40);
            blob[offset++] = (byte)(expiry >> 32);
            blob[offset++] = (byte)(expiry >> 24);
            blob[offset++] = (byte)(expiry >> 16);
            blob[offset++] = (byte)(expiry >>  8);
            blob[offset++] = (byte)(expiry      );

            Buffer.BlockCopy(nonce,        0, blob, offset, NonceSize);         offset += NonceSize;
            Buffer.BlockCopy(tag,          0, blob, offset, TagSize);           offset += TagSize;
            Buffer.BlockCopy(ciphertext,   0, blob, offset, ciphertext.Length); offset += ciphertext.Length;
            Buffer.BlockCopy(ephemeralKey, 0, blob, offset, EphemeralKeySize);

            CryptographicOperations.ZeroMemory(ephemeralKey);

            var tmp = SessionPath + ".tmp";
            File.WriteAllBytes(tmp, blob);
            try { File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
            File.Move(tmp, SessionPath, overwrite: true);

            CryptographicOperations.ZeroMemory(blob);
        }
        catch { }
    }

    /// <summary>
    /// Reads and decrypts the session file, returning the cached master password.
    /// </summary>
    /// <returns>
    /// The master password if a valid, non-expired session exists; otherwise <see langword="null"/>.
    /// </returns>
    /// <remarks>
    /// Returns <see langword="null"/> and calls <see cref="Delete"/> if the session has
    /// expired, is malformed, or if decryption fails (which would indicate the file was
    /// tampered with). Callers should prompt for the master password whenever
    /// <see langword="null"/> is returned.
    /// </remarks>
    public static string? TryLoad()
    {
        try
        {
            if (!File.Exists(SessionPath))
                return null;

            var blob = File.ReadAllBytes(SessionPath);

            if (blob.Length < MinFileSize)
            {
                Delete();
                return null;
            }

            int offset = 0;
            long expiry = 0;
            for (int i = 0; i < ExpirySize; i++)
                expiry = (expiry << 8) | blob[offset++];

            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= expiry)
            {
                Delete();
                return null;
            }

            var nonce         = blob[offset..(offset + NonceSize)];        offset += NonceSize;
            var tag           = blob[offset..(offset + TagSize)];          offset += TagSize;
            int ciphertextLen = blob.Length - MinFileSize;
            var ciphertext    = blob[offset..(offset + ciphertextLen)];    offset += ciphertextLen;
            var ephemeralKey  = blob[offset..(offset + EphemeralKeySize)];

            var plaintext = new byte[ciphertextLen];
            try
            {
                using var aes = new AesGcm(ephemeralKey, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(ephemeralKey);
            }
        }
        catch
        {
            Delete();
            return null;
        }
    }

    /// <summary>
    /// Deletes the session file, forcing the next command to re-prompt for the master password.
    /// Silently ignores errors (e.g. file already absent).
    /// </summary>
    public static void Delete()
    {
        try { File.Delete(SessionPath); } catch { }
    }
}
