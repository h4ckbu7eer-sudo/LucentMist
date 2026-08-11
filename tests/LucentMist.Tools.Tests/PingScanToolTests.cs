using LucentMist.Tools.Scanning;

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

    private static PingScanTool CreateTool() =>
        new(Microsoft.Extensions.Logging.Abstractions.NullLogger<PingScanTool>.Instance);
}
