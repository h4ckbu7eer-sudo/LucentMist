using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Scanning;

namespace LucentMist.Tools.Tests;

public sealed class GetMyIpToolTests
{
    [Fact]
    public async Task Execute_ReturnsLocalIpAndSuggestedSlash24WithoutExternalCall()
    {
        var tool = new GetMyIpTool(() =>
        [
            new LocalNetworkEntry("Ethernet", "192.168.2.37", 20, "192.168.0.1"),
        ]);

        var result = await tool.ExecuteAsync([]);
        using var doc = JsonDocument.Parse(result.Data);

        Assert.True(result.Success);
        Assert.Equal("192.168.2.37", doc.RootElement.GetProperty("primaryIp").GetString());
        Assert.Equal("192.168.2.0/24", doc.RootElement.GetProperty("suggestedSubnet").GetString());
        var item = Assert.Single(doc.RootElement.GetProperty("interfaces").EnumerateArray());
        Assert.Equal("192.168.0.0/20", item.GetProperty("actualSubnet").GetString());
    }

    [Theory]
    [InlineData("10.20.30.40", 24, "10.20.30.0/24")]
    [InlineData("172.20.31.250", 16, "172.20.0.0/16")]
    [InlineData("192.168.2.37", 20, "192.168.0.0/20")]
    public void ToNetworkCidr_ComputesNetworkBoundary(
        string ip,
        int prefix,
        string expected)
    {
        Assert.Equal(expected, GetMyIpTool.ToNetworkCidr(ip, prefix));
    }

    [Fact]
    public async Task Execute_NoUsableInterface_ReturnsVisibleFailure()
    {
        var result = await new GetMyIpTool(() => []).ExecuteAsync([]);

        Assert.False(result.Success);
        Assert.Contains("未检测到", result.Error);
    }
}
