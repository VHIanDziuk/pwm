using System.Security.Cryptography;

namespace Pwm;

/// <summary>
/// RFC 6238 Time-based One-Time Password implementation using HMAC-SHA-1.
/// </summary>
/// <remarks>
/// Uses no external dependencies — all cryptographic primitives come from
/// <see cref="System.Security.Cryptography"/>. Only the standard Base32 alphabet
/// (A–Z, 2–7) is accepted; padding characters are stripped before decoding.
/// </remarks>
static class Totp
{
    private const int Step   = 30;
    private const int Digits = 6;

    /// <summary>
    /// Decodes a Base32-encoded string (RFC 4648) into raw bytes.
    /// </summary>
    /// <remarks>
    /// Leading/trailing whitespace, internal spaces, and trailing <c>=</c> padding are
    /// all stripped before decoding, which matches the format used by most authenticator
    /// apps and QR-code provisioning URIs.
    /// </remarks>
    private static byte[] DecodeBase32(string input)
    {
        input = input.Trim().TrimEnd('=').ToUpperInvariant().Replace(" ", "");
        if (input.Length == 0) return [];

        var bits = new System.Text.StringBuilder();
        foreach (var ch in input)
        {
            int val;
            if (ch >= 'A' && ch <= 'Z')      val = ch - 'A';
            else if (ch >= '2' && ch <= '7') val = ch - '2' + 26;
            else throw new FormatException($"Invalid Base32 character: '{ch}'");
            bits.Append(Convert.ToString(val, 2).PadLeft(5, '0'));
        }

        var bitStr    = bits.ToString();
        var byteCount = bitStr.Length / 8;
        var result    = new byte[byteCount];
        for (int i = 0; i < byteCount; i++)
            result[i] = Convert.ToByte(bitStr.Substring(i * 8, 8), 2);
        return result;
    }

    /// <summary>
    /// Computes a HOTP/TOTP code for the given HMAC-SHA-1 <paramref name="key"/> and
    /// <paramref name="counter"/> value (RFC 4226 §5.3 dynamic truncation).
    /// </summary>
    /// <param name="key">Raw bytes of the shared TOTP secret.</param>
    /// <param name="counter">Time-step counter derived from Unix time / 30.</param>
    /// <returns>A zero-padded decimal string of <see cref="Digits"/> length.</returns>
    private static string ComputeCode(byte[] key, long counter)
    {
        var counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash   = hmac.ComputeHash(counterBytes);
        int offset = hash[^1] & 0x0F;
        int binary =
            ((hash[offset]     & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) <<  8) |
             (hash[offset + 3] & 0xFF);

        int otp = binary % (int)Math.Pow(10, Digits);
        return otp.ToString().PadLeft(Digits, '0');
    }

    private static long GetCounter(DateTimeOffset time) => time.ToUnixTimeSeconds() / Step;

    /// <summary>
    /// Generates the current TOTP code for a Base32-encoded secret.
    /// </summary>
    /// <param name="base32Secret">The Base32-encoded shared secret from the vault entry.</param>
    public static string GenerateCode(string base32Secret)
    {
        var key = DecodeBase32(base32Secret);
        return ComputeCode(key, GetCounter(DateTimeOffset.UtcNow));
    }

    /// <summary>
    /// Validates a user-supplied TOTP <paramref name="code"/> against the shared secret,
    /// allowing a ±1 time-step tolerance to compensate for clock skew.
    /// </summary>
    /// <param name="base32Secret">The Base32-encoded shared secret stored in the vault entry.</param>
    /// <param name="code">The 6-digit code entered by the user.</param>
    /// <returns>
    /// <see langword="true"/> if the code matches the current, previous, or next time window;
    /// <see langword="false"/> otherwise.
    /// </returns>
    /// <remarks>
    /// The ±30-second window (one step on each side) is the tolerance recommended by
    /// RFC 6238 §5.2 and accepted by virtually all TOTP-protected services.
    /// </remarks>
    public static bool Verify(string base32Secret, string code)
    {
        var  key     = DecodeBase32(base32Secret);
        long counter = GetCounter(DateTimeOffset.UtcNow);
        for (long delta = -1; delta <= 1; delta++)
            if (ComputeCode(key, counter + delta) == code)
                return true;
        return false;
    }
}
