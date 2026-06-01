using System.Text.Json;
using System.Text.Json.Serialization;

namespace Pwm;

/// <summary>
/// Shared request/response types and JSON serialisation helpers for the pwmd socket protocol.
/// </summary>
/// <remarks>
/// The protocol is newline-delimited JSON over a Unix domain socket.
/// Each exchange is one request line followed by one response line.
/// </remarks>
static class DaemonProtocol
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition      = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize<T>(T value) =>
        JsonSerializer.Serialize(value, JsonOptions);

    public static T? Deserialize<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, JsonOptions);
}

/// <summary>
/// A request sent by a <c>pwm</c> client to the running <c>pwmd</c> daemon.
/// </summary>
record DaemonRequest(
    /// <summary>The operation to perform: "unlock", "get", "list", "save", "stop", "ping".</summary>
    string Command,
    /// <summary>The master password (only populated for the "unlock" command).</summary>
    string? Password  = null,
    /// <summary>Entry name for "get" command.</summary>
    string? Name      = null,
    /// <summary>Tag filter for "list" command.</summary>
    string? Tag       = null,
    /// <summary>Serialised List&lt;VaultEntry&gt; JSON for "save" command.</summary>
    string? EntriesJson = null,
    /// <summary>PBKDF2 iteration count to use when saving.</summary>
    int     Iterations  = 0);

/// <summary>
/// A response sent by the daemon back to the client.
/// </summary>
record DaemonResponse(
    bool    Ok,
    string? Error       = null,
    /// <summary>Serialised VaultEntry JSON for "get" responses.</summary>
    string? EntryJson   = null,
    /// <summary>Serialised List&lt;string&gt; JSON for "list" responses.</summary>
    string? NamesJson   = null,
    /// <summary>Serialised List&lt;VaultEntry&gt; JSON for internal vault sync.</summary>
    string? EntriesJson = null,
    /// <summary>True when the vault is currently unlocked in the daemon.</summary>
    bool    Unlocked    = false);
