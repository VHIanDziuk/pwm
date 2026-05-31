using System.CommandLine;
using System.Security.Cryptography;
using System.Text.Json;

namespace Pwm;

static class Commands
{
    public static RootCommand Build()
    {
        var root = new RootCommand("pwm — password manager");

        root.AddCommand(BuildAdd());
        root.AddCommand(BuildGet());
        root.AddCommand(BuildList());
        root.AddCommand(BuildUpdate());
        root.AddCommand(BuildDelete());
        root.AddCommand(BuildExport());
        root.AddCommand(BuildImport());
        root.AddCommand(BuildGenerate());
        root.AddCommand(BuildLock());

        return root;
    }

    // Returns master password from an active session or by prompting the user.
    private static string ObtainMasterPassword()
    {
        var fromSession = SessionStore.TryLoad();
        if (fromSession is not null)
            return fromSession;
        return ReadPassword("Master password: ");
    }

    // Persists a session token after a successful vault unlock.
    private static void PersistSession(string master) =>
        SessionStore.TrySave(master, ttlSeconds: 900);

    private static Command BuildAdd()
    {
        var nameArg = new Argument<string>("name");
        var totpOpt = new Option<string?>("--totp-secret", "Base32-encoded TOTP secret (optional)");
        var cmd = new Command("add", "Add a new entry") { nameArg, totpOpt };

        cmd.SetHandler((string name, string? totpSecret) =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            if (entries.Any(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine($"Error: entry '{name}' already exists.");
                Environment.Exit(1);
            }

            var username = Prompt("Username: ");
            var password = ReadPassword("Password: ");
            var url      = Prompt("URL: ");
            var notes    = Prompt("Notes: ");

            entries.Add(new VaultEntry(name, username, password, url, notes, totpSecret));
            VaultStore.Save(entries, master);
        }, nameArg, totpOpt);

        return cmd;
    }

    private static Command BuildGet()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("get", "Retrieve an entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            var entry = entries.FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                Console.Error.WriteLine($"Error: entry '{name}' not found.");
                Environment.Exit(1);
                return;
            }

            if (entry.TotpSecret is not null)
            {
                var code = ReadPassword("TOTP code: ");
                if (!Totp.Verify(entry.TotpSecret, code.Trim()))
                {
                    Console.Error.WriteLine("Error: invalid TOTP code.");
                    Environment.Exit(1);
                    return;
                }
            }

            Console.WriteLine($"Name:     {entry.Name}");
            Console.WriteLine($"Username: {entry.Username}");
            Console.WriteLine($"Password: {entry.Password}");
            Console.WriteLine($"URL:      {entry.Url}");
            Console.WriteLine($"Notes:    {entry.Notes}");
        }, nameArg);

        return cmd;
    }

    private static Command BuildList()
    {
        var cmd = new Command("list", "List all entry names");

        cmd.SetHandler(() =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            var names = entries.Select(e => e.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
            if (names.Count == 0) { Console.WriteLine("(no entries)"); return; }
            foreach (var n in names) Console.WriteLine(n);
        });

        return cmd;
    }

    private static Command BuildUpdate()
    {
        var nameArg = new Argument<string>("name");
        var totpOpt = new Option<string?>("--totp-secret", "Base32-encoded TOTP secret (empty string to clear)");
        var cmd = new Command("update", "Update an existing entry") { nameArg, totpOpt };

        cmd.SetHandler((string name, string? totpSecret) =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            var idx = entries.FindIndex(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
            if (idx < 0)
            {
                Console.Error.WriteLine($"Error: entry '{name}' not found.");
                Environment.Exit(1);
                return;
            }

            var old = entries[idx];

            var username = PromptWithCurrent("Username", old.Username);
            var password = PromptPasswordWithCurrent("Password", old.Password);
            var url      = PromptWithCurrent("URL", old.Url);
            var notes    = PromptWithCurrent("Notes", old.Notes);

            // --totp-secret supplied: empty string clears it, non-empty sets it; null keeps existing.
            string? newTotp = totpSecret is not null
                ? (totpSecret.Length > 0 ? totpSecret : null)
                : old.TotpSecret;

            entries[idx] = new VaultEntry(old.Name, username, password, url, notes, newTotp);
            VaultStore.Save(entries, master);
        }, nameArg, totpOpt);

        return cmd;
    }

    private static Command BuildDelete()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("delete", "Delete an entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            var idx = entries.FindIndex(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
            if (idx < 0)
            {
                Console.Error.WriteLine($"Error: entry '{name}' not found.");
                Environment.Exit(1);
                return;
            }

            Console.Write($"Delete '{name}'? [y/N] ");
            var answer = Console.ReadLine() ?? string.Empty;
            if (!answer.Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Aborted.");
                return;
            }

            entries.RemoveAt(idx);
            VaultStore.Save(entries, master);
        }, nameArg);

        return cmd;
    }

    private static Command BuildExport()
    {
        var outOpt = new Option<string?>("--out", "Output file path (default: ./pwm-export-<timestamp>.json)");
        var cmd = new Command("export", "Export vault entries to a plaintext JSON file") { outOpt };

        cmd.SetHandler((string? outPath) =>
        {
            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            var resolvedPath = outPath ?? $"./pwm-export-{DateTime.UtcNow:yyyyMMddHHmmss}.json";

            Console.WriteLine("WARNING: This file is unencrypted. Store it securely.");

            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(resolvedPath, json);

            Console.WriteLine(resolvedPath);
        }, outOpt);

        return cmd;
    }

    private static Command BuildImport()
    {
        var pathArg      = new Argument<string>("path", "Path to a pwm export JSON file");
        var overwriteOpt = new Option<bool>("--overwrite", "Overwrite existing entries with imported ones");
        var cmd = new Command("import", "Import vault entries from a plaintext JSON file") { pathArg, overwriteOpt };

        cmd.SetHandler((string path, bool overwrite) =>
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"Error: file '{path}' not found.");
                Environment.Exit(1);
                return;
            }

            List<VaultEntry> imported;
            try
            {
                var json = File.ReadAllText(path);
                imported = JsonSerializer.Deserialize<List<VaultEntry>>(json)
                    ?? throw new InvalidOperationException("Empty or null JSON.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error reading import file: {ex.Message}");
                Environment.Exit(1);
                return;
            }

            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            int importedCount = 0;
            int skippedCount  = 0;

            foreach (var entry in imported)
            {
                var idx = entries.FindIndex(e => string.Equals(e.Name, entry.Name, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    if (overwrite)
                    {
                        entries[idx] = entry;
                        importedCount++;
                    }
                    else
                    {
                        Console.WriteLine($"Skipped: {entry.Name}");
                        skippedCount++;
                    }
                }
                else
                {
                    entries.Add(entry);
                    importedCount++;
                }
            }

            VaultStore.Save(entries, master);
            Console.WriteLine($"Imported {importedCount} entries, skipped {skippedCount}.");
        }, pathArg, overwriteOpt);

        return cmd;
    }

    private static Command BuildGenerate()
    {
        var nameArg      = new Argument<string>("name");
        var lengthOpt    = new Option<int>("--length", () => 24, "Password length (default 24)");
        var noSymbolsOpt = new Option<bool>("--no-symbols", () => false, "Exclude symbols from the character set");
        var cmd = new Command("generate", "Generate a random password and store it as a new entry")
        {
            nameArg, lengthOpt, noSymbolsOpt
        };

        cmd.SetHandler((string name, int length, bool noSymbols) =>
        {
            if (length < 1)
            {
                Console.Error.WriteLine("Error: --length must be at least 1.");
                Environment.Exit(1);
                return;
            }

            var master = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            PersistSession(master);

            if (entries.Any(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine($"Error: entry '{name}' already exists.");
                Environment.Exit(1);
                return;
            }

            const string upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lower   = "abcdefghijklmnopqrstuvwxyz";
            const string digits  = "0123456789";
            const string symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";

            var charset  = upper + lower + digits + (noSymbols ? string.Empty : symbols);
            var password = GeneratePassword(charset, length);

            var username = Prompt("Username (optional): ");
            var url      = Prompt("URL (optional): ");
            var notes    = Prompt("Notes (optional): ");

            entries.Add(new VaultEntry(name, username, password, url, notes));
            VaultStore.Save(entries, master);

            Console.WriteLine($"Generated password: {password}");
        }, nameArg, lengthOpt, noSymbolsOpt);

        return cmd;
    }

    private static Command BuildLock()
    {
        var cmd = new Command("lock", "Expire the current session token");
        cmd.SetHandler(() =>
        {
            SessionStore.Delete();
            Console.WriteLine("Session locked.");
        });
        return cmd;
    }

    private static string GeneratePassword(string charset, int length)
    {
        int n     = charset.Length;
        int limit = (256 / n) * n; // rejection threshold to avoid modulo bias
        var result = new System.Text.StringBuilder(length);
        Span<byte> buf = stackalloc byte[1];

        while (result.Length < length)
        {
            RandomNumberGenerator.Fill(buf);
            int b = buf[0];
            if (b < limit)
                result.Append(charset[b % n]);
        }

        return result.ToString();
    }

    private static string ReadPassword(string prompt)
    {
        if (prompt.Length > 0) Console.Write(prompt);

        // When stdin is redirected (tests, scripts), ReadKey throws — fall back to ReadLine.
        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? string.Empty;

        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) { sb.Remove(sb.Length - 1, 1); Console.Write("\b \b"); }
                continue;
            }
            sb.Append(key.KeyChar);
            Console.Write('*');
        }
        return sb.ToString();
    }

    private static string Prompt(string label)
    {
        Console.Write(label);
        return Console.ReadLine() ?? string.Empty;
    }

    private static string PromptWithCurrent(string label, string current)
    {
        Console.Write($"{label} [{current}]: ");
        var input = Console.ReadLine() ?? string.Empty;
        return input.Length > 0 ? input : current;
    }

    private static string PromptPasswordWithCurrent(string label, string current)
    {
        Console.Write($"{label} [leave blank to keep]: ");
        var input = ReadPassword(string.Empty);
        return input.Length > 0 ? input : current;
    }

    private static void WrongPassword()
    {
        Console.Error.WriteLine("Error: wrong master password.");
        Environment.Exit(1);
    }
}
