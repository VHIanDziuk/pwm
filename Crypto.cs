using System.Security.Cryptography;
using System.Text;

namespace Pwm;

static class Crypto
{
    private const int SaltSize   = 16;
    private const int NonceSize  = 12;
    private const int TagSize    = 16;
    private const int KeySize    = 32;
    private const int Iterations = 600_000;

    public static byte[] DeriveKey(string password, byte[] salt) =>
        DeriveKey(password, salt, Iterations);

    public static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySize);
    }

    public static byte[] Encrypt(string plaintext, string password) =>
        Encrypt(plaintext, password, Iterations);

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
