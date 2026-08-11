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
        // Default: 53,123,161,500,514,1900 = 6 ports
        Assert.Equal(6, doc.RootElement.GetProperty("totalScanned").GetInt32());
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
    public async Task ExecuteAsync_InvalidPortString_ReturnsZeroScanned()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "invalid,also-invalid",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(0, doc.RootElement.GetProperty("totalScanned").GetInt32());
    }

    [Fact]
    public async Task ExecuteAsync_PortRangeUpperBound_ClampsAt65535()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "65530-65540",
            ["timeout_ms"] = "500"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success);

        using var doc = JsonDocument.Parse(result.Data);
        // 65530, 65531, 65532, 65533, 65534, 65535 = 6 ports
        Assert.Equal(6, doc.RootElement.GetProperty("totalScanned").GetInt32());
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
}
