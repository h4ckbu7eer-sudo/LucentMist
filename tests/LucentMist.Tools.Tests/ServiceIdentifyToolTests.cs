using LucentMist.Tools.Scanning;

namespace LucentMist.Tools.Tests;

public class ServiceIdentifyToolTests
{
    [Fact]
    public void Tool_Name_ReturnsServiceIdentify() =>
        Assert.Equal("service_identify", CreateTool().Name);

    [Fact]
    public async Task Execute_EmptyTarget_Fails()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "", ["port"] = "80" });
        Assert.False(r.Success);
    }

    [Fact]
    public async Task Execute_InvalidPort_Fails()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "127.0.0.1", ["port"] = "99999" });
        Assert.False(r.Success);
    }

    [Theory]
    [InlineData("22", "ssh")]
    [InlineData("80", "http")]
    [InlineData("443", "https")]
    [InlineData("53", "dns")]
    [InlineData("3306", "mysql")]
    [InlineData("6379", "redis")]
    [InlineData("3389", "rdp")]
    [InlineData("5432", "postgresql")]
    public async Task Execute_KnownPort_MapsCorrectly(string port, string expected)
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1", ["port"] = port, ["timeout_ms"] = "100"
        });
        Assert.True(r.Success);
        Assert.Contains(expected, r.Data.ToLower());
    }

    [Fact]
    public async Task Execute_UnknownPort_ReturnsUnknown()
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1", ["port"] = "12345", ["timeout_ms"] = "100"
        });
        Assert.True(r.Success);
        Assert.Contains("unknown", r.Data.ToLower());
    }

    [Fact]
    public async Task Execute_ContainsAllFields()
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1", ["port"] = "80", ["timeout_ms"] = "500"
        });
        Assert.Contains("target", r.Data);
        Assert.Contains("port", r.Data);
        Assert.Contains("serviceName", r.Data);
        Assert.Contains("banner", r.Data);
    }

    private static ServiceIdentifyTool CreateTool() =>
        new(Microsoft.Extensions.Logging.Abstractions.NullLogger<ServiceIdentifyTool>.Instance);
}
