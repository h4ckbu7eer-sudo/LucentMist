#:project ../src/LucentMist.Tools/LucentMist.Tools.csproj
#:property LangVersion=14.0
#:property PublishAot=false
#:property RestorePackagesWithLockFile=false

using System.Text.Json;
using System.Text.Encodings.Web;
using LucentMist.Core.Networking;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging.Abstractions;

// Explicit opt-in diagnostic: real tools and real APIs, NOT a model conversation.
if (args.Length != 2 || args[0] != "--authorized-target")
{
    Console.Error.WriteLine("Usage: dotnet run --file scripts/validate-cloud-gateway.cs -- --authorized-target <your gateway>");
    return 2;
}
var target = args[1];
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
var ct = deadline.Token;
var result = new Dictionary<string, object?>
{
    ["evidenceType"] = "real tools + real APIs; not an LLM dialogue",
    ["utc"] = DateTimeOffset.UtcNow,
    ["externalSetting"] = Environment.GetEnvironmentVariable("LMIST_CVE_EXTERNAL") ?? "unset (default enabled)",
    ["llmKeyConfigured"] = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_LLM_APIKEY")),
    ["builtInRuleCount"] = CveDatabase.Entries.Count,
};
var ip = await new GetMyIpTool().ExecuteAsync(new ToolArguments(), ct);
using var ipDoc = JsonDocument.Parse(ip.Data);
result["primaryIp"] = ipDoc.RootElement.GetProperty("primaryIp").GetString();
result["primaryInterface"] = ipDoc.RootElement.GetProperty("primaryInterface").GetString();
result["injectedNetworkContext"] = LocalNetworkInfo.InjectLocalNetworkInfo("看看我的ip", LocalNetworkInfo.GetEntries());

var scan = await new PortScanTool(NullLogger<PortScanTool>.Instance).ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = "53,80,443", ["timeout_ms"] = "1000" }, ct);
if (!scan.Success) { Console.Error.WriteLine(scan.Error); return 1; }
using var portsDoc = JsonDocument.Parse(scan.Data);
var ports = portsDoc.RootElement.GetProperty("openPorts").EnumerateArray().Select(p => p.GetInt32()).ToArray();
result["openPorts"] = ports;
if (ports.Length > 0)
{
    var vulnerability = await new VulnerabilityScanTool().ExecuteAsync(new ToolArguments
    {
        ["target"] = target, ["open_ports"] = string.Join(',', ports), ["timeout_ms"] = "3000",
    }, ct);
    if (!vulnerability.Success) { Console.Error.WriteLine(vulnerability.Error); return 1; }
    using var doc = JsonDocument.Parse(vulnerability.Data);
    result["vulnerability"] = doc.RootElement.EnumerateObject()
        .Where(p => p.Name is "overallRisk" or "totalFindings" or "cloudCandidateCount" or "cloudNotice" or "sourceChecks" or "checkedServices" or "portSelection")
        .ToDictionary(p => p.Name, p => p.Value.Clone());
}
if (ports.Contains(443))
{
    var ssl = await new SslCertificateTool(NullLogger<SslCertificateTool>.Instance).ExecuteAsync(new ToolArguments { ["target"] = target, ["port"] = "443" }, ct);
    if (!ssl.Success) result["sslError"] = ssl.Error;
    else
    {
        using var doc = JsonDocument.Parse(ssl.Data);
        result["ssl"] = doc.RootElement.EnumerateObject().Where(p => p.Name is "isExpired" or "isTrusted" or "trustErrors")
            .ToDictionary(p => p.Name, p => p.Value.Clone());
    }
}
// This is a public software-coordinate lookup, not a claim about the gateway's SSH service.
var cloud = await CveApiClient.QueryWithStatusAsync("SSH", "SSH-2.0-OpenSSH_9.8p1", 22, ct);
result["publicOpenSshCoordinateQuery"] = new
{
    sources = cloud.Sources,
    count = cloud.Items.Count,
    allUnverified = cloud.Items.All(c => c.VersionStatus == "unverified"),
    incorrectlyIncludesFixed201815473 = cloud.Items.Any(c => c.Cve == "CVE-2018-15473"),
};
Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
return 0;
