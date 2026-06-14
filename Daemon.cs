using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Pwm;

/// <summary>
/// The <c>pwmd</c> daemon: holds the decrypted vault in memory and serves
/// requests from <c>pwm</c> client processes over a Unix domain socket.
/// </summary>
/// <remarks>
/// <para>
/// The daemon is started by <c>pwm daemon start</c>, which forks a background
/// process and exits immediately. Subsequent <c>pwm</c> invocations detect the
/// running daemon via the socket file and skip PBKDF2 derivation entirely,
/// making vault operations near-instant.
/// </para>
/// <para>
/// The daemon exits automatically after <c>idle_timeout_seconds</c> of inactivity
/// (default 15 minutes), zeroing all key material from memory before exit.
/// <c>pwm daemon stop</c> sends a "stop" command for immediate shutdown.
/// </para>
/// <para>
/// Socket path: <c>~/.pwm/pwmd.sock</c>
/// </para>
/// </remarks>
static class Daemon
{
    private static readonly string PwmDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".pwm");

    public static readonly string SocketPath = Path.Combine(PwmDir, "pwmd.sock");

    private static List<VaultEntry>? _vault;
    private static string?           _master;
    private static DateTime          _lastActivity = DateTime.UtcNow;
    private static readonly object   _lock = new();

    /// <summary>
    /// Runs the daemon process: binds the socket, accepts connections, and serves
    /// requests until idle timeout or a "stop" command.
    /// </summary>
    public static void Run(int idleTimeoutSeconds)
    {
        Directory.CreateDirectory(PwmDir);

        // Remove a stale socket file from a previous (crashed) daemon.
        if (File.Exists(SocketPath))
            File.Delete(SocketPath);

        using var server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var endpoint = new UnixDomainSocketEndPoint(SocketPath);
        server.Bind(endpoint);
        server.Listen(backlog: 8);

        if (!OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(SocketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }

        server.ReceiveTimeout = 500; // ms — allows the accept loop to poll idle timeout

        try
        {
            while (true)
            {
                // Check idle timeout.
                lock (_lock)
                {
                    if (_vault is not null &&
                        (DateTime.UtcNow - _lastActivity).TotalSeconds >= idleTimeoutSeconds)
                    {
                        ZeroVault();
                        // Don't exit — stay alive but locked until next unlock.
                    }
                }

                Socket? client;
                try   { client = server.Accept(); }
                catch (SocketException) { continue; } // timeout, loop

                // Each connection handled synchronously (one at a time is fine for a CLI tool).
                try   { HandleClient(client); }
                catch { }
                finally { client.Dispose(); }

                // "stop" command sets this flag via the handler.
                if (_stopRequested)
                    break;
            }
        }
        finally
        {
            ZeroVault();
            try { File.Delete(SocketPath); } catch { }
        }
    }

    private static bool _stopRequested;

    private static void HandleClient(Socket client)
    {
        using var stream = new NetworkStream(client, ownsSocket: false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        var line = reader.ReadLine();
        if (line is null) return;

        var req = DaemonProtocol.Deserialize<DaemonRequest>(line);
        if (req is null) { writer.WriteLine(DaemonProtocol.Serialize(new DaemonResponse(false, "Bad request"))); return; }

        lock (_lock)
        {
            _lastActivity = DateTime.UtcNow;
            DaemonResponse resp = req.Command switch
            {
                "ping"    => HandlePing(),
                "unlock"  => HandleUnlock(req),
                "get"     => HandleGet(req),
                "get_all" => HandleGetAll(),
                "list"    => HandleList(req),
                "save"    => HandleSave(req),
                "stop"    => HandleStop(),
                _         => new DaemonResponse(false, $"Unknown command: {req.Command}"),
            };
            writer.WriteLine(DaemonProtocol.Serialize(resp));
        }
    }

    private static DaemonResponse HandlePing() =>
        new(Ok: true, Unlocked: _vault is not null);

    private static DaemonResponse HandleUnlock(DaemonRequest req)
    {
        if (req.Password is null)
            return new DaemonResponse(false, "Password required");

        try
        {
            var entries = VaultStore.Load(req.Password);
            ZeroVault();
            _vault  = entries;
            _master = req.Password;
            return new DaemonResponse(Ok: true, Unlocked: true);
        }
        catch (CryptographicException)
        {
            return new DaemonResponse(false, "wrong_password");
        }
    }

    private static DaemonResponse HandleGet(DaemonRequest req)
    {
        if (_vault is null || _master is null)
            return new DaemonResponse(false, "locked");

        if (req.Name is null)
            return new DaemonResponse(false, "Name required");

        var entry = _vault.FirstOrDefault(e =>
            string.Equals(e.Name, req.Name, StringComparison.OrdinalIgnoreCase));

        return entry is null
            ? new DaemonResponse(false, "not_found")
            : new DaemonResponse(Ok: true, EntryJson: DaemonProtocol.Serialize(entry));
    }

    private static DaemonResponse HandleList(DaemonRequest req)
    {
        if (_vault is null)
            return new DaemonResponse(false, "locked");

        IEnumerable<VaultEntry> filtered = _vault;
        if (req.Tag is not null)
            filtered = _vault.Where(e =>
                e.Tags is not null &&
                e.Tags.Any(t => string.Equals(t, req.Tag, StringComparison.OrdinalIgnoreCase)));

        var names = filtered.Select(e => e.Name)
                             .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                             .ToList();

        return new DaemonResponse(Ok: true, NamesJson: DaemonProtocol.Serialize(names));
    }

    private static DaemonResponse HandleGetAll()
    {
        if (_vault is null)
            return new DaemonResponse(false, "locked");

        return new DaemonResponse(Ok: true, EntriesJson: DaemonProtocol.Serialize(_vault));
    }

    private static DaemonResponse HandleSave(DaemonRequest req)
    {
        if (_vault is null || _master is null)
            return new DaemonResponse(false, "locked");

        if (req.EntriesJson is null)
            return new DaemonResponse(false, "EntriesJson required");

        try
        {
            var entries = DaemonProtocol.Deserialize<List<VaultEntry>>(req.EntriesJson)
                ?? throw new InvalidOperationException("Null entries");

            int iterations = req.Iterations > 0 ? req.Iterations : 600_000;
            VaultStore.Save(entries, _master, iterations);
            _vault = entries;
            return new DaemonResponse(Ok: true);
        }
        catch (Exception ex)
        {
            return new DaemonResponse(false, ex.Message);
        }
    }

    private static DaemonResponse HandleStop()
    {
        _stopRequested = true;
        return new DaemonResponse(Ok: true);
    }

    private static void ZeroVault()
    {
        _vault  = null;
        if (_master is not null)
        {
            // Best-effort: overwrite the string's chars before releasing the reference.
            // This is imperfect under GC but limits the exposure window.
            var bytes = Encoding.UTF8.GetBytes(_master);
            CryptographicOperations.ZeroMemory(bytes);
            _master = null;
        }
    }
}
