using System.Net.NetworkInformation;
using System.Text.Json;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class PingScanToolTests
{
    [Fact]
    public void Tool_Name_ReturnsPingScan() =>
        Assert.Equal("ping_scan", CreateTool().Name);

    [Fact]
    public void Tool_Description_NotEmpty() =>
        Assert.False(string.IsNullOrEmpty(CreateTool().Description));

    [Fact]
    public void Parameters_HasRequiredTarget()
    {
        var p = CreateTool().Parameters.First(x => x.Name == "target");
        Assert.True(p.Required);
    }

    [Fact]
    public async Task Execute_EmptyTarget_Fails()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "" });
        Assert.False(r.Success);
    }

    [Fact]
    public async Task Execute_Localhost_Alive()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        Assert.True(r.Success);
        Assert.Contains("\"alive\":1", r.Data);
    }

    [Fact]
    public async Task Execute_Hostname_IsNotSilentlyEmpty()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "localhost", ["timeout_ms"] = "2000" });

        Assert.True(r.Success);
        Assert.DoesNotContain("\"total\":0", r.Data);
    }

    [Theory]
    [InlineData("127.0.0.1/32", 1)]
    [InlineData("10.0.0.0/31", 2)]
    public void ParseTarget_SupportsPointToPointCidr(string target, int expected)
    {
        var ips = CreateTool().ParseTarget(target);

        Assert.Equal(expected, ips.Count);
    }

    [Fact]
    public async Task Execute_ContainsAllFields()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        Assert.Contains("target", r.Data);
        Assert.Contains("total", r.Data);
        Assert.Contains("alive", r.Data);
        Assert.Contains("devices", r.Data);
        Assert.True(r.Duration.TotalMilliseconds > 0);
    }

    [Theory]
    [InlineData(IPStatus.DestinationUnreachable)]
    [InlineData(IPStatus.DestinationHostUnreachable)]
    [InlineData(IPStatus.DestinationProtocolUnreachable)]
    [InlineData(IPStatus.DestinationPortUnreachable)]
    public async Task Execute_IcmpReject_UsesTcpFallback(IPStatus rejectStatus)
    {
        var tcpCalls = 0;
        var tool = new PingScanTool(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<PingScanTool>.Instance,
            (_, _, _) => Task.FromResult(rejectStatus),
            (_, _, _) =>
            {
                Interlocked.Increment(ref tcpCalls);
                return Task.FromResult(true);
            });

        var result = await tool.ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1",
            ["timeout_ms"] = "200"
        });

        Assert.True(result.Success, result.Error);
        Assert.Equal(1, tcpCalls);
        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(1, doc.RootElement.GetProperty("alive").GetInt32());
        var fallback = doc.RootElement.GetProperty("icmpFallback").GetString();
        Assert.Contains("ICMP 被拒绝", fallback);
        Assert.DoesNotContain("ICMP 无响应", fallback);
    }

    [Fact]
    public async Task Execute_IcmpTimeout_ReportsNoResponseFallback()
    {
        var tool = new PingScanTool(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<PingScanTool>.Instance,
            (_, _, _) => Task.FromResult(IPStatus.TimedOut),
            (_, _, _) => Task.FromResult(true));

        var result = await tool.ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1",
            ["timeout_ms"] = "200"
        });

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        var fallback = doc.RootElement.GetProperty("icmpFallback").GetString();
        Assert.Contains("ICMP 无响应", fallback);
        Assert.DoesNotContain("ICMP 被拒绝", fallback);
    }

    [Fact]
    public void ShouldFallbackToTcp_NonReachabilityFailure_DoesNotFallback()
    {
        Assert.False(PingScanTool.ShouldFallbackToTcp(IPStatus.BadOption));
    }

    [Fact]
    public void TcpFallbackPorts_CoverDeclaredHighRiskDiscoveryPorts()
    {
        foreach (var port in VulnerabilityScanTool.DefaultScanPorts)
            Assert.Contains(port, PingScanTool.TcpFallbackPorts);
        Assert.Contains(53, PingScanTool.TcpFallbackPorts);
        Assert.Contains(3389, PingScanTool.TcpFallbackPorts);
        Assert.Contains(27017, PingScanTool.TcpFallbackPorts);
    }

    private static PingScanTool CreateTool() =>
        new(Microsoft.Extensions.Logging.Abstractions.NullLogger<PingScanTool>.Instance);
}
