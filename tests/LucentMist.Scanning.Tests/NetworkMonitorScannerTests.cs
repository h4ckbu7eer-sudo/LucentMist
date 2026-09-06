using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using LucentMist.Tools;

namespace LucentMist.Scanning.Tests;

public class NetworkMonitorScannerTests
{
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.99.0/24", "22,80,443");
    private static ToolResult Ok(object data) => ToolResult.Ok(JsonSerializer.Serialize(data), TimeSpan.Zero);
    private static FakeTool Discovery(int devices = 1) => new((_, _) => Task.FromResult(Ok(new
    {
        deviceDetails = Enumerable.Range(1, devices).Select(n => new { ip = $"192.168.99.{n}", mac = $"00:11:22:33:44:{n:D2}", vendor = "known", name = "device" }),
    })));
    private static FakeTool Never => new((_, _) => throw new InvalidOperationException("Unexpected tool execution"));

    [Fact]
    public async Task FailedDiscoveryDoesNotRunPortsOrClaimEmptySuccess()
    {
        var scanner = new NetworkMonitorScanner(new FakeTool((_, _) => Task.FromResult(ToolResult.Fail("denied", TimeSpan.Zero))), Never, Never, Never);
        var snapshot = await scanner.CaptureAsync(Scope, false, default);
        Assert.False(snapshot.DiscoverySucceeded);
        Assert.Equal("denied", snapshot.Error);
    }

    [Fact]
    public async Task AndroidIdentityEvidenceSurvivesDiscoveryAndPortScanning()
    {
        var discovery = new FakeTool((_, _) => Task.FromResult(Ok(new
        {
            deviceDetails = new[] { new { ip = "192.168.99.10", mac = "02:11:22:33:44:55", vendor = "随机 MAC", name = "android-99.local", model = "Test-Phone", mdnsServices = new[] { "_adb._tcp.local" } } },
        })));
        var scanner = new NetworkMonitorScanner(discovery, new FakeTool((_, _) => Task.FromResult(Ok(new { openPorts = Array.Empty<int>() }))), Never, Never);
        var device = Assert.Single((await scanner.CaptureAsync(Scope, false, default)).Devices);
        Assert.Equal("Test-Phone", device.Model);
        Assert.Equal("android-99.local", device.Name);
        Assert.Contains("_adb._tcp.local", device.MdnsServices!);
    }

    [Fact]
    public async Task FailedPortScanIsNull_NotEmptySuccessfulScan_AndDoesNotRunVulnerabilities()
    {
        var scanner = new NetworkMonitorScanner(Discovery(), new FakeTool((_, _) => Task.FromResult(ToolResult.Fail("probe failed", TimeSpan.Zero))), Never, Never);
        var snapshot = await scanner.CaptureAsync(Scope, true, default);
        Assert.True(snapshot.DiscoverySucceeded);
        Assert.Null(Assert.Single(snapshot.Devices).OpenPorts);
    }

    [Fact]
    public async Task VulnerabilityOptInReusesSuccessfulOpenPorts_ExcludesCloudLeads_AndFlagsPartial()
    {
        var vuln = new FakeTool((args, _) =>
        {
            Assert.Equal("22,443", args["open_ports"]);
            Assert.Equal("succeeded", args["port_scan_status"]);
            Assert.Equal("false", args["use_nmap"]);
            return Task.FromResult(Ok(new
            {
                findings = new[] { new { port = 22, cve = "CVE-2024-6387" } },
                cloudCandidates = new[] { new { port = 443, cve = "CVE-2020-0001" } },
                checkedServices = new[] { new { port = 22, banner = "SSH-2.0-OpenSSH_9.2p1" } },
                externalPartial = true,
            }));
        });
        var scanner = new NetworkMonitorScanner(Discovery(), new FakeTool((_, _) => Task.FromResult(Ok(new { openPorts = new[] { 22, 443 } }))), Never, vuln);
        var device = Assert.Single((await scanner.CaptureAsync(Scope, true, default)).Devices);
        Assert.Equal(new[] { "22:CVE-2024-6387" }, device.Vulnerabilities);
        Assert.Contains("云源覆盖不完整", device.Warnings!);
        Assert.Contains("openssh", device.Services![22], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DefaultIsLocalServiceChecks_NoCloudVulnerabilityOrNmapExecution()
    {
        var scanner = new NetworkMonitorScanner(Discovery(), new FakeTool((args, _) =>
        {
            Assert.Equal("16", args["concurrency"]);
            return Task.FromResult(Ok(new { openPorts = new[] { 80 } }));
        }), new FakeTool((args, _) =>
        {
            Assert.Equal("80", args["port"]);
            return Task.FromResult(Ok(new { banner = "nginx/1.24.0" }));
        }), Never);
        var device = Assert.Single((await scanner.CaptureAsync(Scope, false, default)).Devices);
        Assert.Null(device.Vulnerabilities);
        Assert.Contains("1.24.0", device.Services![80]);
    }

    [Fact]
    public async Task DeviceConcurrencyIsBoundedAtTwo()
    {
        var active = 0;
        var maximum = 0;
        var ports = new FakeTool(async (_, ct) =>
        {
            var current = Interlocked.Increment(ref active);
            Interlocked.Exchange(ref maximum, Math.Max(Volatile.Read(ref maximum), current));
            await Task.Delay(20, ct);
            Interlocked.Decrement(ref active);
            return Ok(new { openPorts = Array.Empty<int>() });
        });
        var scanner = new NetworkMonitorScanner(Discovery(10), ports, Never, Never);
        var snapshot = await scanner.CaptureAsync(Scope, false, default);
        Assert.Equal(10, snapshot.Devices.Length);
        Assert.InRange(maximum, 1, 2);
        Assert.Equal(0, active);
    }

    private sealed class FakeTool(Func<ToolArguments, CancellationToken, Task<ToolResult>> run) : ITool
    {
        public string Name => "fake";
        public string Description => "deterministic test tool";
        public ToolParameter[] Parameters => [];
        public Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default) => run(args, cancellationToken);
    }
}
