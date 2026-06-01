namespace Pwm;

class PwmConfig
{
    public int SessionTtlSeconds     { get; set; } = 900;
    public int ClipboardClearSeconds { get; set; } = 30;
    public int Pbkdf2Iterations      { get; set; } = 600_000;

    private static readonly string ConfigPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pwm", "config.toml");

    public static PwmConfig Load()
    {
        var cfg = new PwmConfig();
        if (!File.Exists(ConfigPath))
            return cfg;

        foreach (var rawLine in File.ReadAllLines(ConfigPath))
        {
            var line = rawLine.Trim();
            var commentIdx = line.IndexOf('#');
            if (commentIdx >= 0) line = line[..commentIdx].Trim();
            if (line.Length == 0) continue;

            var eq = line.IndexOf('=');
            if (eq < 0) continue;

            var key   = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();

            switch (key)
            {
                case "session_ttl_seconds"     when int.TryParse(value, out var v) && v > 0:
                    cfg.SessionTtlSeconds = v; break;
                case "clipboard_clear_seconds" when int.TryParse(value, out var v) && v > 0:
                    cfg.ClipboardClearSeconds = v; break;
                case "pbkdf2_iterations"       when int.TryParse(value, out var v) && v >= 100_000:
                    cfg.Pbkdf2Iterations = v; break;
            }
        }

        return cfg;
    }
}
