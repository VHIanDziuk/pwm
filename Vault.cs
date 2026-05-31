using System.Text.Json;

namespace Pwm;

record VaultEntry(
    string  Name,
    string  Username,
    string  Password,
    string  Url,
    string  Notes,
    string? TotpSecret = null);

static class VaultStore
{
    private static readonly string VaultDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pwm");

    private static readonly string VaultPath = Path.Combine(VaultDir, "vault.enc");

    public static List<VaultEntry> Load(string masterPassword)
    {
        Directory.CreateDirectory(VaultDir);

        if (!File.Exists(VaultPath))
            return [];

        var blob = File.ReadAllBytes(VaultPath);
        var json = Crypto.Decrypt(blob, masterPassword);
        return JsonSerializer.Deserialize<List<VaultEntry>>(json)!;
    }

    public static void Save(List<VaultEntry> entries, string masterPassword)
    {
        Directory.CreateDirectory(VaultDir);

        var json = JsonSerializer.Serialize(entries);
        var blob = Crypto.Encrypt(json, masterPassword);

        var tmp = VaultPath + ".tmp";
        File.WriteAllBytes(tmp, blob);
        File.Move(tmp, VaultPath, overwrite: true);
    }
}
