using System.Net.Sockets;
using System.Text;

namespace Pwm;

/// <summary>
/// Client-side helper for communicating with a running <c>pwmd</c> daemon over
/// its Unix domain socket.
/// </summary>
/// <remarks>
/// Each method opens a fresh connection, sends one request, reads one response,
/// and closes. This keeps the client stateless and avoids connection management.
/// All methods return <see langword="null"/> (or an appropriate sentinel) when the
/// daemon is unreachable, so callers can fall back to direct vault access.
/// </remarks>
static class DaemonClient
{
    private const int ConnectTimeoutMs = 300;

    /// <summary>
    /// Returns <see langword="true"/> if a pwmd daemon is running and reachable.
    /// </summary>
    public static bool IsRunning()
    {
        var resp = Send(new DaemonRequest("ping"));
        return resp?.Ok == true;
    }

    /// <summary>
    /// Sends the master password to the daemon so it can unlock the vault.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> on success; <see langword="false"/> if the password was
    /// wrong or the daemon could not be reached.
    /// </returns>
    public static bool Unlock(string masterPassword)
    {
        var resp = Send(new DaemonRequest("unlock", Password: masterPassword));
        return resp?.Ok == true;
    }

    /// <summary>
    /// Requests a single vault entry from the daemon by name.
    /// </summary>
    /// <returns>
    /// The matching <see cref="VaultEntry"/>, or <see langword="null"/> if not found,
    /// the vault is locked, or the daemon is unreachable.
    /// </returns>
    public static (VaultEntry? entry, string? error) Get(string name)
    {
        var resp = Send(new DaemonRequest("get", Name: name));
        if (resp is null)           return (null, "daemon_unreachable");
        if (!resp.Ok)               return (null, resp.Error);
        if (resp.EntryJson is null) return (null, "empty_response");

        var entry = DaemonProtocol.Deserialize<VaultEntry>(resp.EntryJson);
        return (entry, null);
    }

    /// <summary>
    /// Requests the list of entry names, optionally filtered by tag.
    /// </summary>
    public static (List<string>? names, string? error) List(string? tag = null)
    {
        var resp = Send(new DaemonRequest("list", Tag: tag));
        if (resp is null)            return (null, "daemon_unreachable");
        if (!resp.Ok)                return (null, resp.Error);
        if (resp.NamesJson is null)  return (null, "empty_response");

        var names = DaemonProtocol.Deserialize<List<string>>(resp.NamesJson);
        return (names, null);
    }

    /// <summary>
    /// Asks the daemon to save the provided entry list and persist the vault to disk.
    /// </summary>
    public static (bool ok, string? error) Save(List<VaultEntry> entries, int iterations)
    {
        var entriesJson = DaemonProtocol.Serialize(entries);
        var resp = Send(new DaemonRequest("save", EntriesJson: entriesJson, Iterations: iterations));
        if (resp is null)  return (false, "daemon_unreachable");
        return (resp.Ok, resp.Error);
    }

    /// <summary>
    /// Asks the daemon to load all entries (for commands that need to mutate the full vault).
    /// Uses "list" under the hood but returns full entries via a dedicated "entries" response.
    /// Actually sends a "get_all" — implemented as an internal protocol extension.
    /// </summary>
    public static (List<VaultEntry>? entries, string? error) GetAll()
    {
        var resp = Send(new DaemonRequest("get_all"));
        if (resp is null)             return (null, "daemon_unreachable");
        if (!resp.Ok)                 return (null, resp.Error);
        if (resp.EntriesJson is null) return (null, "empty_response");

        var entries = DaemonProtocol.Deserialize<List<VaultEntry>>(resp.EntriesJson);
        return (entries, null);
    }

    /// <summary>Sends a stop command to the daemon.</summary>
    public static void Stop() => Send(new DaemonRequest("stop"));

    /// <summary>
    /// Sends a status/ping request and returns whether the daemon is unlocked.
    /// </summary>
    public static bool? GetUnlockedStatus()
    {
        var resp = Send(new DaemonRequest("ping"));
        if (resp is null) return null;
        return resp.Unlocked;
    }

    // ── internal ──────────────────────────────────────────────────────────────

    private static DaemonResponse? Send(DaemonRequest req)
    {
        if (!File.Exists(Daemon.SocketPath))
            return null;

        try
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);

            // Connect with a short timeout so a stale socket file doesn't hang the CLI.
            var connectTask = socket.ConnectAsync(new UnixDomainSocketEndPoint(Daemon.SocketPath));
            if (!connectTask.Wait(ConnectTimeoutMs))
            {
                socket.Close();
                return null;
            }

            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
            using var reader = new StreamReader(stream, Encoding.UTF8);

            writer.WriteLine(DaemonProtocol.Serialize(req));
            var line = reader.ReadLine();
            if (line is null) return null;

            return DaemonProtocol.Deserialize<DaemonResponse>(line);
        }
        catch
        {
            return null;
        }
    }
}
