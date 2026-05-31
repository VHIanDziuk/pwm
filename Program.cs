using System.CommandLine;
using Pwm;

var root = Commands.Build();
return root.Invoke(args);
