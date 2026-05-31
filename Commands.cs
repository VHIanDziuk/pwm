using System.CommandLine;
using System.Security.Cryptography;

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

        return root;
    }

    private static Command BuildAdd()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("add", "Add a new entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ReadPassword("Master password: ");
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            if (entries.Any(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                Console.Error.WriteLine($"Error: entry '{name}' already exists.");
                Environment.Exit(1);
            }

            var username = Prompt("Username: ");
            var password = ReadPassword("Password: ");
            var url      = Prompt("URL: ");
            var notes    = Prompt("Notes: ");

            entries.Add(new VaultEntry(name, username, password, url, notes));
            VaultStore.Save(entries, master);
        }, nameArg);

        return cmd;
    }

    private static Command BuildGet()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("get", "Retrieve an entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ReadPassword("Master password: ");
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            var entry = entries.FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                Console.Error.WriteLine($"Error: entry '{name}' not found.");
                Environment.Exit(1);
                return;
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
            var master = ReadPassword("Master password: ");
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

            var names = entries.Select(e => e.Name).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
            if (names.Count == 0)
            {
                Console.WriteLine("(no entries)");
                return;
            }
            foreach (var n in names)
                Console.WriteLine(n);
        });

        return cmd;
    }

    private static Command BuildUpdate()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("update", "Update an existing entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ReadPassword("Master password: ");
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

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

            entries[idx] = new VaultEntry(old.Name, username, password, url, notes);
            VaultStore.Save(entries, master);
        }, nameArg);

        return cmd;
    }

    private static Command BuildDelete()
    {
        var nameArg = new Argument<string>("name");
        var cmd = new Command("delete", "Delete an entry") { nameArg };

        cmd.SetHandler((string name) =>
        {
            var master = ReadPassword("Master password: ");
            List<VaultEntry> entries;
            try { entries = VaultStore.Load(master); }
            catch (CryptographicException) { WrongPassword(); return; }

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

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    Console.Write("\b \b");
                }
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
