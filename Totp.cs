using System.Security.Cryptography;

namespace Pwm;

static class Totp
{
    private const int Step   = 30;
    private const int Digits = 6;

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

    public static string GenerateCode(string base32Secret)
    {
        var key = DecodeBase32(base32Secret);
        return ComputeCode(key, GetCounter(DateTimeOffset.UtcNow));
    }

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
