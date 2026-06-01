using System.CommandLine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Pwm;

static class Commands
{
    public static RootCommand Build()
    {
        var config = PwmConfig.Load();
        var root = new RootCommand("pwm — password manager");

        root.AddCommand(BuildAdd(config));
        root.AddCommand(BuildGet(config));
        root.AddCommand(BuildList(config));
        root.AddCommand(BuildUpdate(config));
        root.AddCommand(BuildDelete(config));
        root.AddCommand(BuildExport(config));
        root.AddCommand(BuildImport(config));
        root.AddCommand(BuildGenerate(config));
        root.AddCommand(BuildLock());

        return root;
    }

    // Returns master password from an active session or by prompting the user,
    // plus whether it came from the session.
    private static (string master, bool fromSession) ObtainMasterPassword()
    {
        var fromSession = SessionStore.TryLoad();
        if (fromSession is not null)
            return (fromSession, true);
        return (ReadPassword("Master password: "), false);
    }

    private static void DecryptFailed(bool usedSession)
    {
        if (usedSession)
            Console.Error.WriteLine("Error: vault is corrupt or has been tampered with.");
        else
            Console.Error.WriteLine("Error: wrong master password (or vault is corrupt/tampered).");
        Environment.Exit(1);
    }

    private static Command BuildAdd(PwmConfig config)
    {
        var nameArg = new Argument<string>("name");
        var totpOpt = new Option<string?>("--totp-secret", "Base32-encoded TOTP secret (optional)");
        var tagOpt  = new Option<string[]>("--tag", "Tag to assign (repeatable)")
        {
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore,
        };
        var cmd = new Command("add", "Add a new entry") { nameArg, totpOpt, tagOpt };

        cmd.SetHandler((string name, string? totpSecret, string[] tags) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

            if (entries.Any(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine($"Error: entry '{name}' already exists.");
                Environment.Exit(1);
            }

            var username = Prompt("Username: ");
            var password = ReadPassword("Password: ");
            var url      = Prompt("URL: ");
            var notes    = Prompt("Notes: ");

            List<string>? tagList = tags.Length > 0 ? [..tags] : null;

            entries.Add(new VaultEntry(name, username, password, url, notes, totpSecret, tagList));
            VaultStore.Save(entries, master, config.Pbkdf2Iterations);
        }, nameArg, totpOpt, tagOpt);

        return cmd;
    }

    private static Command BuildGet(PwmConfig config)
    {
        var nameArg = new Argument<string>("name");
        var clipOpt = new Option<bool>("--clip", "Copy password to clipboard instead of printing it");
        var cmd = new Command("get", "Retrieve an entry") { nameArg, clipOpt };

        cmd.SetHandler((string name, bool clip) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

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

            if (clip)
            {
                CopyToClipboard(entry.Password);
                ScheduleClipboardClear(config.ClipboardClearSeconds);
                Console.Error.WriteLine($"Password copied to clipboard (cleared in {config.ClipboardClearSeconds}s)");
            }
            else
            {
                Console.WriteLine($"Password: {entry.Password}");
            }

            Console.WriteLine($"URL:      {entry.Url}");
            Console.WriteLine($"Notes:    {entry.Notes}");

            if (entry.Tags is { Count: > 0 })
                Console.WriteLine($"Tags:     {string.Join(", ", entry.Tags)}");
        }, nameArg, clipOpt);

        return cmd;
    }

    private static Command BuildList(PwmConfig config)
    {
        var tagOpt = new Option<string?>("--tag", "Filter entries by tag");
        var cmd = new Command("list", "List all entry names") { tagOpt };

        cmd.SetHandler((string? tag) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

            IEnumerable<VaultEntry> filtered = entries;
            if (tag is not null)
                filtered = entries.Where(e =>
                    e.Tags is not null &&
                    e.Tags.Any(t => string.Equals(t, tag, StringComparison.OrdinalIgnoreCase)));

            var names = filtered.Select(e => e.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
            if (names.Count == 0) { Console.WriteLine("(no entries)"); return; }
            foreach (var n in names) Console.WriteLine(n);
        }, tagOpt);

        return cmd;
    }

    private static Command BuildUpdate(PwmConfig config)
    {
        var nameArg = new Argument<string>("name");
        var totpOpt = new Option<string?>("--totp-secret", "Base32-encoded TOTP secret (empty string to clear)");
        var tagOpt  = new Option<string[]>("--tag", "Replace all tags (repeatable; omit to keep existing)")
        {
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore,
        };
        var cmd = new Command("update", "Update an existing entry") { nameArg, totpOpt, tagOpt };

        cmd.SetHandler((string name, string? totpSecret, string[] tags) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

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

            string? newTotp = totpSecret is not null
                ? (totpSecret.Length > 0 ? totpSecret : null)
                : old.TotpSecret;

            // --tag present on command line replaces all tags; absent keeps old.
            bool tagFlagPresent = Environment.GetCommandLineArgs()
                .Any(a => string.Equals(a, "--tag", StringComparison.OrdinalIgnoreCase));
            List<string>? newTags = tagFlagPresent
                ? (tags.Length > 0 ? [..tags] : null)
                : old.Tags;

            entries[idx] = new VaultEntry(old.Name, username, password, url, notes, newTotp, newTags);
            VaultStore.Save(entries, master, config.Pbkdf2Iterations);
        }, nameArg, totpOpt, tagOpt);

        return cmd;
    }

    private static Command BuildDelete(PwmConfig config)
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("delete", "Delete an entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

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
            VaultStore.Save(entries, master, config.Pbkdf2Iterations);
        }, nameArg);

        return cmd;
    }

    private static Command BuildExport(PwmConfig config)
    {
        var outOpt = new Option<string?>("--out", "Output file path (default: ./pwm-export-<timestamp>.json)");
        var cmd = new Command("export", "Export vault entries to a plaintext JSON file") { outOpt };

        cmd.SetHandler((string? outPath) =>
        {
            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

            var resolvedPath = outPath ?? $"./pwm-export-{DateTime.UtcNow:yyyyMMddHHmmss}.json";

            Console.WriteLine("WARNING: This file is unencrypted. Store it securely.");

            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(resolvedPath, json);

            Console.WriteLine(resolvedPath);
        }, outOpt);

        return cmd;
    }

    private static Command BuildImport(PwmConfig config)
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

            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

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

            VaultStore.Save(entries, master, config.Pbkdf2Iterations);
            Console.WriteLine($"Imported {importedCount} entries, skipped {skippedCount}.");
        }, pathArg, overwriteOpt);

        return cmd;
    }

    private static Command BuildGenerate(PwmConfig config)
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

            var (master, fromSession) = ObtainMasterPassword();
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { DecryptFailed(fromSession); return; }

            SessionStore.TrySave(master, ttlSeconds: config.SessionTtlSeconds);

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
            VaultStore.Save(entries, master, config.Pbkdf2Iterations);

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

    private static void CopyToClipboard(string text)
    {
        ProcessStartInfo psi;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            psi = new ProcessStartInfo { FileName = "pbcopy", RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            psi = new ProcessStartInfo { FileName = "xclip", Arguments = "-selection clipboard", RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        else
            psi = new ProcessStartInfo { FileName = "clip", RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };

        using var proc = Process.Start(psi)!;
        proc.StandardInput.Write(text);
        proc.StandardInput.Close();
        proc.WaitForExit();
    }

    private static void ScheduleClipboardClear(int delaySecs)
    {
        ProcessStartInfo psi;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            psi = new ProcessStartInfo { FileName = "sh", Arguments = $"-c \"sleep {delaySecs} && echo -n '' | pbcopy\"", UseShellExecute = false, CreateNoWindow = true };
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            psi = new ProcessStartInfo { FileName = "sh", Arguments = $"-c \"sleep {delaySecs} && echo -n '' | xclip -selection clipboard\"", UseShellExecute = false, CreateNoWindow = true };
        else
            psi = new ProcessStartInfo { FileName = "cmd", Arguments = $"/c \"timeout /t {delaySecs} /nobreak >nul && echo. | clip\"", UseShellExecute = false, CreateNoWindow = true };

        Process.Start(psi); // fire-and-forget
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
}
