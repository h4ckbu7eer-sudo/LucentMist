using System.Text;
using System.Text.Json;
using LucentMist.CLI;
using LucentMist.Scanning.Monitoring;

// Test-only executable: commands, storage, locking and rendering are the real CLI.
// Only the network boundary and local subnet discovery are supplied as fixtures.
Console.OutputEncoding = Encoding.UTF8;
var fixture = Environment.GetEnvironmentVariable("LMIST_TEST_SNAPSHOT") ?? throw new InvalidOperationException("Missing fixture");
var subnet = Environment.GetEnvironmentVariable("LMIST_TEST_SUBNET") ?? throw new InvalidOperationException("Missing subnet");
var app = new CliApp(async (_, _, ct) =>
    JsonSerializer.Deserialize<NetworkSnapshot>(await File.ReadAllTextAsync(fixture, ct)) ?? throw new InvalidDataException("Missing snapshot"),
    _ => Task.FromResult(subnet));
return await app.RunAsync(args);
