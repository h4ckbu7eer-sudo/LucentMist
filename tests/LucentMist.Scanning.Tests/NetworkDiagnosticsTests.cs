using System.Net.NetworkInformation;
using System.Net.Sockets;
using LucentMist.Core.Networking;
using LucentMist.Scanning.Monitoring;

namespace LucentMist.Scanning.Tests;

public class NetworkDiagnosticsTests
{
    private static List<LocalNetworkEntry> Interfaces() =>
        [new("Wi-Fi", "192.168.99.9", 24, "192.168.99.1") { InterfaceType = NetworkInterfaceType.Wireless80211 }];
    private static NetworkDiagnostics Diagnostics(bool gateway, bool dns, bool internet) => new(Interfaces,
        (_, _) => Task.FromResult(gateway), (_, _) => Task.FromResult(dns), _ => Task.FromResult(internet), () => ["127.0.0.1:5050"]);

    [Fact]
    public async Task DnsFailureWithWorkingInternetPointsToDns_NotWholeNetwork()
    {
        var report = await Diagnostics(true, false, true).RunAsync();
        Assert.Contains(report.Checks, c => c.Layer == "dns" && c.Status == "failed");
        Assert.Contains(report.Suggestions, s => s.Contains("公网 TCP 可达但 DNS 解析失败"));
        Assert.Contains(report.Checks, c => c.Layer == "listeners" && c.Evidence.Contains("不等于公网暴露"));
    }

    [Fact]
    public async Task GatewayProbeRejectDoesNotClaimGatewayDeadWhenInternetWorks()
    {
        var report = await Diagnostics(false, true, true).RunAsync();
        Assert.Contains(report.Suggestions, s => s.Contains("不能断言网关掉线"));
    }

    [Fact]
    public async Task AllTestEndpointsFail_DoesNotClaimWholeInternetDown()
    {
        var report = await Diagnostics(true, true, false).RunAsync();
        Assert.Contains(report.Suggestions, s => s.Contains("不据此断言整个互联网断网"));
        Assert.Contains(report.Checks, c => c.Layer == "internet" && c.Evidence.Contains("0/3"));
    }

    [Fact]
    public async Task OneEndpointRejects_TheOthersStillRun_AndProveConnectivity()
    {
        var calls = new System.Collections.Concurrent.ConcurrentBag<string>();
        var diagnostics = new NetworkDiagnostics(Interfaces, (_, _) => Task.FromResult(true), (_, _) => Task.FromResult(true),
            listeners: () => [], internetEndpoint: (address, port, _) =>
            {
                calls.Add(address + ":" + port);
                if (address == "1.1.1.1") throw new SocketException();
                return Task.FromResult(true);
            });
        var report = await diagnostics.RunAsync();
        Assert.Equal(3, calls.Count);
        Assert.Contains(report.Checks, c => c.Layer == "internet" && c.Status == "ok" && c.Evidence.Contains("2/3") && c.Evidence.Contains("1.1.1.1:443"));
        Assert.Contains(report.Suggestions, s => s.Contains("不代表整体断网"));
    }

    [Fact]
    public void LoopbackAndHighPortsAreFolded_NotDeclaredSafe_AndCanBeExpanded()
    {
        string[] ports = ["127.0.0.1:5050", "[::1]:5051", "0.0.0.0:80", "[::]:443", "0.0.0.0:50001"];
        var compact = NetworkDiagnostics.DescribeListeners(ports);
        Assert.Contains("0.0.0.0:80", compact);
        Assert.Contains("[::]:443", compact);
        Assert.DoesNotContain("127.0.0.1:5050", compact);
        Assert.DoesNotContain("0.0.0.0:50001", compact);
        Assert.Contains("折叠回环 2 项", compact);
        Assert.Contains("高位不等于安全", compact);
        Assert.Contains("0.0.0.0:50001", NetworkDiagnostics.DescribeListeners(ports, all: true));
    }

    [Fact]
    public async Task NoExternalSkipsTheTcpProbe_ButDnsStillRuns()
    {
        var calls = 0;
        var diagnostics = new NetworkDiagnostics(Interfaces, (_, _) => Task.FromResult(true), (_, _) => { calls++; return Task.FromResult(true); },
            _ => throw new InvalidOperationException("must not reach internet"), () => []);
        var report = await diagnostics.RunAsync(external: false);
        Assert.Equal(1, calls);
        Assert.Contains(report.Checks, c => c.Layer == "internet" && c.Status == "skipped");
    }

    [Fact]
    public async Task ProbeExceptionIsVisibleAsFailure_NotSilentSuccess()
    {
        var diagnostics = new NetworkDiagnostics(Interfaces, (_, _) => Task.FromResult(true), (_, _) => throw new SocketException(),
            _ => Task.FromResult(true), () => []);
        var report = await diagnostics.RunAsync();
        Assert.Contains(report.Checks, c => c.Layer == "dns" && c.Status == "failed" && c.Evidence.Contains("失败/超时"));
    }

    [Fact]
    public async Task CallerCancellationPropagates()
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Diagnostics(true, true, true).RunAsync(ct: stop.Token));
    }

    [Fact]
    public async Task MissingPhysicalInterfaceIsWarning_NotInventedGateway()
    {
        var diagnostics = new NetworkDiagnostics(() => [], (_, _) => throw new InvalidOperationException("no gateway"),
            (_, _) => Task.FromResult(false), _ => Task.FromResult(false), () => []);
        var report = await diagnostics.RunAsync();
        Assert.Contains(report.Checks, c => c.Layer == "interface" && c.Status == "warning");
        Assert.Contains(report.Checks, c => c.Layer == "gateway" && c.Status == "skipped");
        Assert.Contains(report.Suggestions, s => s.Contains("不会下发路由规则"));
    }
}
