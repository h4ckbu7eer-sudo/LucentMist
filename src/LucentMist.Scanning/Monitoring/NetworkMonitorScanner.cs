using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;
using Microsoft.Extensions.Logging;

namespace LucentMist.Scanning.Monitoring;

public sealed class NetworkMonitorScanner(ITool discovery, ITool portScan, ITool serviceIdentify, ITool vulnerabilityScan)
{
    public NetworkMonitorScanner(ILoggerFactory logger) : this(new PingScanTool(logger.CreateLogger<PingScanTool>()),
        new PortScanTool(logger.CreateLogger<PortScanTool>()), new ServiceIdentifyTool(logger.CreateLogger<ServiceIdentifyTool>()),
        new VulnerabilityScanTool(logger.CreateLogger<VulnerabilityScanTool>()))
    { }

    public async Task<NetworkSnapshot> CaptureAsync(MonitorScope scope, bool checkVulnerabilities, CancellationToken ct)
    {
        var guard = await TargetGuard.ValidateAsync(scope.Subnet, ct);
        if (!guard.IsAllowed || guard.RequiresPublicAuthorization) return new(false, [], "目标授权策略拒绝监控。");
        var result = await discovery.ExecuteAsync(new() { ["target"] = scope.Subnet, ["timeout_ms"] = "800", ["concurrency"] = "32" }, ct);
        if (!result.Success) return new(false, [], result.Error);
        using var parsed = JsonDocument.Parse(result.Data);
        var details = parsed.RootElement.GetProperty("deviceDetails").EnumerateArray().ToArray();
        var devices = new MonitorDevice[details.Length];
        await Parallel.ForEachAsync(Enumerable.Range(0, details.Length), new ParallelOptions { MaxDegreeOfParallelism = 2, CancellationToken = ct }, async (index, token) =>
        {
            var detail = details[index];
            var ip = Text(detail, "ip");
            var mac = Text(detail, "mac");
            var vendor = Text(detail, "vendor");
            var name = Text(detail, "name");
            var model = Text(detail, "model");
            var mdnsServices = Strings(detail, "mdnsServices");
            var ports = await portScan.ExecuteAsync(new() { ["target"] = ip, ["ports"] = scope.Ports, ["timeout_ms"] = "800", ["concurrency"] = "16" }, token);
            if (!ports.Success) { devices[index] = new(ip, mac, vendor, name, null, Model: model, MdnsServices: mdnsServices); return; }
            using var portData = JsonDocument.Parse(ports.Data);
            var open = portData.RootElement.GetProperty("openPorts").EnumerateArray().Select(p => p.GetInt32()).ToArray();
            if (portData.RootElement.TryGetProperty("device", out var identity))
            {
                if (Meaningful(Text(identity, "vendor"))) vendor = Text(identity, "vendor");
                if (Meaningful(Text(identity, "name"))) name = Text(identity, "name");
                if (Meaningful(Text(identity, "model"))) model = Text(identity, "model");
                mdnsServices = mdnsServices.Union(Strings(identity, "mdnsServices")).ToArray();
                mac = MonitorDevice.NormalizeMac(Text(identity, "mac")) ?? mac;
            }
            var services = new Dictionary<int, string>();
            var warnings = new List<string>();
            string[]? risks = null;
            if (checkVulnerabilities)
            {
                var vulnerability = await vulnerabilityScan.ExecuteAsync(new()
                {
                    ["target"] = ip,
                    ["ports"] = scope.Ports,
                    ["open_ports"] = string.Join(',', open),
                    ["port_scan_status"] = "succeeded",
                    ["use_nmap"] = "false",
                    ["timeout_ms"] = "1500",
                }, token);
                if (vulnerability.Success)
                {
                    using var data = JsonDocument.Parse(vulnerability.Data);
                    if (data.RootElement.TryGetProperty("externalPartial", out var partial) && partial.GetBoolean()) warnings.Add("云源覆盖不完整");
                    risks = data.RootElement.GetProperty("findings").EnumerateArray()
                        .Select(f => $"{f.GetProperty("port")}:{Text(f, "cve")}").Distinct().Order().ToArray();
                    foreach (var check in data.RootElement.GetProperty("checkedServices").EnumerateArray())
                        AddService(check.GetProperty("port").GetInt32(), Text(check, "banner"));
                }
                else warnings.Add("漏洞扫描失败");
            }
            else
            {
                foreach (var port in open)
                {
                    var service = await serviceIdentify.ExecuteAsync(new() { ["target"] = ip, ["port"] = port.ToString(), ["timeout_ms"] = "1000" }, token);
                    if (!service.Success) { warnings.Add($"{port} 服务识别失败"); continue; }
                    using var data = JsonDocument.Parse(service.Data);
                    AddService(port, Text(data.RootElement, "banner"));
                }
            }
            devices[index] = new(ip, mac, vendor, name, open, services, risks, warnings.ToArray(), model, mdnsServices);
            void AddService(int port, string banner)
            {
                var fingerprint = ServiceFingerprint.FromBanner(banner);
                if (fingerprint != null) services[port] = fingerprint.ProductKey + (fingerprint.Version == null ? "" : "/" + fingerprint.Version);
            }
        });
        return new(true, devices);
    }
    private static string Text(JsonElement item, string key) => item.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
    private static string[] Strings(JsonElement item, string key) => item.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Array
        ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).Distinct().ToArray() : [];
    private static bool Meaningful(string value) => value.Length > 0 && !value.StartsWith("未知", StringComparison.Ordinal);
}
