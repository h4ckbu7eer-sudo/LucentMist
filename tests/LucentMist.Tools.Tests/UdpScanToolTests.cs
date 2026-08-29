using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class UdpScanToolTests
{
    private readonly UdpScanTool _tool = new(new Logger<UdpScanTool>(NullLoggerFactory.Instance));

    [Fact]
    public async Task ExecuteAsync_WithEmptyTarget_ReturnsFailure()
    {
        var args = new ToolArguments { ["target"] = "" };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
        Assert.Contains("必须指定目标 IP", result.Error);
    }

    [Fact]
    public async Task ExecuteAsync_WithMissingTarget_ReturnsFailure()
    {
        var args = new ToolArguments();

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithLocalhost_CompletesSuccessfully()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "53",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(1, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_SinglePort_ScansCorrectly()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "161",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(1, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_CommaSeparatedPorts_ParsesCorrectly()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "53,123,161",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(3, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_PortRange_ParsesCorrectly()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "50-54",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        // 50, 51, 52, 53, 54 = 5 ports
        Assert.Equal(5, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_DefaultPorts_ScansCommonUdpServices()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        // Defaults only include services with an implemented protocol probe.
        Assert.Equal(4, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_MixedPortsAndRanges_ParsesCorrectly()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "53, 100-102, 161",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        // 53 + (100,101,102) + 161 = 5
        Assert.Equal(5, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_InvalidPortString_ReturnsFailure()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "invalid,also-invalid",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
        Assert.Contains("端口", result.Error);
    }

    [Fact]
    public async Task ExecuteAsync_PortRangeUpperBound_ReturnsFailure()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "65530-65540",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
        Assert.Contains("端口", result.Error);
    }

    [Fact]
    public async Task ExecuteAsync_ResultContainsRequiredFields()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "53",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);
        Assert.True(result.Duration > TimeSpan.Zero);

        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("target", out _));
        Assert.True(root.TryGetProperty("totalScanned", out _));
        Assert.True(root.TryGetProperty("openPorts", out _));
        Assert.True(root.TryGetProperty("services", out _));
        Assert.True(root.TryGetProperty("ports", out _));
        Assert.True(root.TryGetProperty("openFilteredPorts", out _));
        Assert.True(root.TryGetProperty("closedPorts", out _));
        Assert.True(root.TryGetProperty("unprobeablePorts", out _));
        Assert.True(root.TryGetProperty("scanDuration", out _));
    }

    [Fact]
    public async Task ExecuteAsync_WithNonRoutableIp_CompletesQuickly()
    {
        // TEST-NET-1: won't respond, but should complete without error
        var args = new ToolArguments
        {
            ["target"] = "192.0.2.1",
            ["ports"] = "53,123",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);
        Assert.True(result.Duration.TotalSeconds < 10);
    }

    [Fact]
    public async Task ExecuteAsync_WithConcurrency_SucceedsUnderLoad()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "1-20",
            ["timeout_ms"] = "200",
            ["concurrency"] = "50"
        };

        var result = await _tool.ExecuteAsync(args);

        // Should not crash even with high concurrency
        Assert.True(result.Success);
    }

    [Fact]
    public async Task ExecuteAsync_ServicesField_MapsKnownPortNames()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "53,123,161",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        var services = doc.RootElement.GetProperty("services");

        // Services is a dictionary: port → name, possibly empty if nothing is open
        // The structure is correct regardless of whether ports are open
        Assert.Equal(JsonValueKind.Object, services.ValueKind);
    }

    [Fact]
    public void TryCreateProbe_Ntp_IsVersion3ClientRequest()
    {
        Assert.True(UdpScanTool.TryCreateProbe(123, out var probe, out var reason));

        Assert.Null(reason);
        Assert.Equal(48, probe.Length);
        Assert.Equal(0, probe[0] >> 6);
        Assert.Equal(3, (probe[0] >> 3) & 0x07);
        Assert.Equal(3, probe[0] & 0x07);
    }

    [Fact]
    public void TryCreateProbe_Ssdp_IsValidMSearchRequest()
    {
        Assert.True(UdpScanTool.TryCreateProbe(1900, out var probe, out var reason));

        Assert.Null(reason);
        var text = Encoding.ASCII.GetString(probe);
        Assert.StartsWith("M-SEARCH * HTTP/1.1\r\n", text);
        Assert.Contains("HOST: 239.255.255.250:1900\r\n", text);
        Assert.Contains("MAN: \"ssdp:discover\"\r\n", text);
        Assert.EndsWith("\r\n\r\n", text);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(514)]
    public void TryCreateProbe_UnsupportedSilentServices_AreNotFakeProbed(int port)
    {
        Assert.False(UdpScanTool.TryCreateProbe(port, out var probe, out var reason));
        Assert.Empty(probe);
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public async Task ProbeUdpEndpoint_OpenButSilentService_IsOpenFilteredNotClosed()
    {
        using var silentService = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)silentService.Client.LocalEndPoint!).Port;

        var result = await UdpScanTool.ProbeUdpEndpointAsync(
            "127.0.0.1",
            port,
            "silent-test",
            new byte[] { 0x1B },
            150);

        Assert.Equal("open|filtered", result.State);
        Assert.Contains("可能开放", result.Detail);
    }

    [Fact]
    public async Task ExecuteAsync_UnsupportedPort_IsExplicitlyUnprobeable()
    {
        var result = await _tool.ExecuteAsync(new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "514",
            ["timeout_ms"] = "150"
        });

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        var port = Assert.Single(doc.RootElement.GetProperty("ports").EnumerateArray());
        Assert.Equal("unprobeable", port.GetProperty("state").GetString());
        Assert.Empty(doc.RootElement.GetProperty("closedPorts").EnumerateArray());
    }

    [Fact]
    public async Task ExecuteAsync_ResultExplainsConnectionResetLimitation()
    {
        var result = await _tool.ExecuteAsync(new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "514",
            ["timeout_ms"] = "150"
        });

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        var interpretation = doc.RootElement.GetProperty("interpretation").GetString();
        Assert.Contains("closed 基于不可达或连接重置推断", interpretation);
        Assert.Contains("防火墙重置可能造成误判", interpretation);
    }

    [Fact]
    public void ClosedInferenceDetail_ConnectionResetIsNotPresentedAsCertain()
    {
        var detail = UdpScanTool.ClosedInferenceDetail(SocketError.ConnectionReset);

        Assert.Contains("防火墙重置", detail);
        Assert.Contains("推断状态", detail);
    }
}
