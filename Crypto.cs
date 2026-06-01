using System.Security.Cryptography;
using System.Text;

namespace Pwm;

/// <summary>
/// Low-level cryptographic helpers for AES-256-GCM encryption and PBKDF2 key derivation.
/// </summary>
/// <remarks>
/// All derived keys are zeroed from memory via <see cref="CryptographicOperations.ZeroMemory"/>
/// immediately after use, even when an exception is thrown, to minimise the window during
/// which key material lives in the GC heap.
/// </remarks>
static class Crypto
{
    private const int SaltSize   = 16;
    private const int NonceSize  = 12;
    private const int TagSize    = 16;
    private const int KeySize    = 32;
    private const int Iterations = 600_000;

    /// <summary>
    /// Derives a 256-bit AES key from <paramref name="password"/> using the default
    /// iteration count (600,000 rounds of PBKDF2-HMAC-SHA-256).
    /// </summary>
    /// <param name="password">The user-supplied master password.</param>
    /// <param name="salt">A cryptographically random salt; must match the salt embedded
    /// in the blob when decrypting.</param>
    public static byte[] DeriveKey(string password, byte[] salt) =>
        DeriveKey(password, salt, Iterations);

    /// <summary>
    /// Derives a 256-bit AES key with a caller-specified iteration count.
    /// </summary>
    /// <param name="password">The user-supplied master password.</param>
    /// <param name="salt">Cryptographically random salt.</param>
    /// <param name="iterations">
    /// PBKDF2 iteration count. Higher values increase resistance to brute-force attacks
    /// at the cost of additional unlock latency. Must not be lower than 100,000.
    /// </param>
    public static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySize);
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-256-GCM with the default iteration count.
    /// </summary>
    public static byte[] Encrypt(string plaintext, string password) =>
        Encrypt(plaintext, password, Iterations);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with AES-256-GCM and returns a self-contained blob.
    /// </summary>
    /// <param name="plaintext">UTF-8 string to encrypt (e.g. JSON-serialised vault).</param>
    /// <param name="password">Master password from which the key is derived.</param>
    /// <param name="iterations">PBKDF2 iteration count forwarded to <see cref="DeriveKey(string,byte[],int)"/>.</param>
    /// <returns>
    /// A byte array with the layout:
    /// <c>[salt (16)] [nonce (12)] [tag (16)] [ciphertext (variable)]</c>.
    /// A fresh random salt and nonce are generated on every call, so encrypting the
    /// same plaintext twice produces different outputs.
    /// </returns>
    public static byte[] Encrypt(string plaintext, string password, int iterations)
    {
        var salt  = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key   = DeriveKey(password, salt, iterations);

        try
        {
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext     = new byte[plaintextBytes.Length];
            var tag            = new byte[TagSize];

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            var blob = new byte[SaltSize + NonceSize + TagSize + ciphertext.Length];
            Buffer.BlockCopy(salt,       0, blob, 0,                              SaltSize);
            Buffer.BlockCopy(nonce,      0, blob, SaltSize,                       NonceSize);
            Buffer.BlockCopy(tag,        0, blob, SaltSize + NonceSize,           TagSize);
            Buffer.BlockCopy(ciphertext, 0, blob, SaltSize + NonceSize + TagSize, ciphertext.Length);
            return blob;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    /// <summary>
    /// Decrypts a blob produced by <see cref="Encrypt(string,string,int)"/>.
    /// </summary>
    /// <param name="blob">The raw bytes read from the vault file.</param>
    /// <param name="password">Master password; the salt embedded in the blob is used to re-derive the key.</param>
    /// <returns>The original plaintext as a UTF-8 string.</returns>
    /// <exception cref="CryptographicException">
    /// Thrown when the password is wrong, the blob is truncated, or the authentication
    /// tag does not match (indicating tampering). The two error cases are deliberately
    /// indistinguishable to prevent oracle attacks.
    /// </exception>
    public static string Decrypt(byte[] blob, string password)
    {
        if (blob.Length < SaltSize + NonceSize + TagSize)
            throw new CryptographicException("Blob is too short.");

        var salt       = blob[..SaltSize];
        var nonce      = blob[SaltSize..(SaltSize + NonceSize)];
        var tag        = blob[(SaltSize + NonceSize)..(SaltSize + NonceSize + TagSize)];
        var ciphertext = blob[(SaltSize + NonceSize + TagSize)..];

        var key = DeriveKey(password, salt);
        try
        {
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return Encoding.UTF8.GetString(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
