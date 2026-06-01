using System.CommandLine;
using Pwm;

// Internal entry point used by "pwm daemon start" to fork the daemon process.
// The parent re-launches this binary with "__daemon <idle_seconds>" as arguments.
if (args.Length >= 1 && args[0] == "__daemon")
{
    int idle = args.Length >= 2 && int.TryParse(args[1], out var s) ? s : 900;
    Daemon.Run(idle);
    return 0;
}

var root = Commands.Build();
return root.Invoke(args);
