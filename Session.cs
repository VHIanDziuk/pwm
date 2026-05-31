using System.Security.Cryptography;
using System.Text;

namespace Pwm;

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

    public static void Delete()
    {
        try { File.Delete(SessionPath); } catch { }
    }
}
