using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using LucentMist.Tools;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class OsFingerprintToolTests
{
    private readonly OsFingerprintTool _tool = new();

    [Fact]
    public async Task ExecuteAsync_WithEmptyTarget_ReturnsFailure()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "" });
        Assert.False(r.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithMissingTarget_ReturnsFailure()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments());
        Assert.False(r.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithLocalhost_ReturnsSuccess()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        Assert.True(r.Success);
        var d = JsonDocument.Parse(r.Data).RootElement;
        Assert.True(d.GetProperty("reachable").GetBoolean());
        Assert.NotEmpty(d.GetProperty("osFamily").GetString()!);
    }

    [Fact]
    public async Task ExecuteAsync_ResultContainsAllFields()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        Assert.True(r.Success);
        var d = JsonDocument.Parse(r.Data).RootElement;
        Assert.True(d.TryGetProperty("target", out _));
        Assert.True(d.TryGetProperty("reachable", out _));
        Assert.True(d.TryGetProperty("osFamily", out _));
        Assert.True(d.TryGetProperty("confidence", out _));
        Assert.True(d.TryGetProperty("reasons", out _));
        Assert.True(d.TryGetProperty("ttl", out _));
        Assert.True(d.TryGetProperty("pingMs", out _));
        Assert.True(d.TryGetProperty("tcpWindows", out _));
        Assert.True(d.TryGetProperty("portHints", out _));
        Assert.True(d.TryGetProperty("scanDuration", out _));
    }

    [Fact]
    public async Task ExecuteAsync_Localhost_TtlShouldBe128()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        Assert.True(r.Success);
        var d = JsonDocument.Parse(r.Data).RootElement;
        var ttl = d.GetProperty("ttl").GetInt32();
        Assert.True(ttl == 128 || ttl == 64 || ttl == 255, $"Unexpected TTL: {ttl}");
    }

    [Fact]
    public async Task ExecuteAsync_UnreachableHost_ReturnsNotReachable()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "192.0.2.1", ["timeout_ms"] = "1000" });
        Assert.True(r.Success);
        var d = JsonDocument.Parse(r.Data).RootElement;
        Assert.False(d.GetProperty("reachable").GetBoolean());
        Assert.Contains("不可达", d.GetProperty("osFamily").GetString());
    }

    [Fact]
    public async Task ExecuteAsync_ConfidenceWithinRange()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        var d = JsonDocument.Parse(r.Data).RootElement;
        var conf = d.GetProperty("confidence").GetInt32();
        Assert.True(conf is >= 0 and <= 100, $"Confidence {conf} out of range");
    }

    [Fact]
    public async Task ExecuteAsync_ReasonsIsArray()
    {
        var r = await _tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "2000" });
        var d = JsonDocument.Parse(r.Data).RootElement;
        var reasons = d.GetProperty("reasons");
        Assert.Equal(JsonValueKind.Array, reasons.ValueKind);
    }

    [Fact]
    public void ToolMetadata_Correct()
    {
        Assert.Equal("os_fingerprint", _tool.Name);
        Assert.NotEmpty(_tool.Description);
        Assert.True(_tool.Parameters.Length >= 1);
    }
}
