namespace Pwm;

/// <summary>
/// Persistent user preferences loaded from <c>~/.pwm/config.toml</c>.
/// </summary>
/// <remarks>
/// The file uses a minimal key = value format; TOML section headers and multi-line
/// values are not supported. Unknown keys are silently ignored so future config
/// options do not break older binaries.  Missing or unparseable values fall back to
/// safe compile-time defaults.
/// </remarks>
class PwmConfig
{
    /// <summary>
    /// How long (in seconds) a session token remains valid after it is written.
    /// Default: 900 (15 minutes).
    /// </summary>
    public int SessionTtlSeconds     { get; set; } = 900;

    /// <summary>
    /// How many seconds after a <c>--clip</c> write before the clipboard is cleared.
    /// Default: 30.
    /// </summary>
    public int ClipboardClearSeconds { get; set; } = 30;

    /// <summary>
    /// PBKDF2-HMAC-SHA-256 iteration count used when saving the vault.
    /// Must be at least 100,000; default is 600,000 per NIST SP 800-132.
    /// Increasing this value after initial setup re-encrypts the vault on the next save.
    /// </summary>
    public int Pbkdf2Iterations      { get; set; } = 600_000;

    /// <summary>
    /// How many seconds the <c>pwmd</c> daemon waits without receiving a request
    /// before zeroing the in-memory vault and locking itself. Default: 900 (15 minutes).
    /// </summary>
    public int DaemonIdleSeconds     { get; set; } = 900;

    private static readonly string ConfigPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pwm", "config.toml");

    /// <summary>
    /// Loads configuration from <c>~/.pwm/config.toml</c>, returning defaults if the
    /// file is absent or contains no recognised keys.
    /// </summary>
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
                case "daemon_idle_seconds"     when int.TryParse(value, out var v) && v > 0:
                    cfg.DaemonIdleSeconds = v; break;
            }
        }

        return cfg;
    }
}
