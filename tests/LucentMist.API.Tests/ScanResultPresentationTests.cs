extern alias LucentMistWeb;
using System.Text.Json;
using ScanPortResult = LucentMistWeb::LucentMist.Web.AppState.ScanPortResult;

namespace LucentMist.API.Tests;

public class ScanResultPresentationTests
{
    [Theory]
    [InlineData("{}", "未取得端口结果")]
    [InlineData("{\"portScanFailures\":{\"127.0.0.1\":\"failed\"}}", "扫描失败")]
    [InlineData("{\"openPortsByIp\":{\"127.0.0.1\":[]}}", "所选端口未观测到开放")]
    [InlineData("{\"openPortsByIp\":{\"127.0.0.1\":[443]}}", "443")]
    public void DiscoveryPortSummaryDistinguishesUnknownFailureAndSuccessfulEmpty(string json, string expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Contains(expected, LucentMistWeb::LucentMist.Web.AppState.DescribeDevicePorts(doc.RootElement, "127.0.0.1"));
    }

    [Fact]
    public void UdpUnknownsRemainVisibleInsteadOfBecomingAnEmptyOpenList()
    {
        using var doc = JsonDocument.Parse("""{"openPorts":[53],"ports":[{"port":53,"service":"DNS","state":"open"},{"port":123,"service":"NTP","state":"open|filtered","detail":"探测超时"},{"port":514,"state":"unprobeable"},{"port":500,"state":"closed"}]}""");
        var rows = ScanPortResult.FromToolResult(doc.RootElement, "udp");
        Assert.Equal(4, rows.Count);
        Assert.Single(rows, r => r.State == "open");
        Assert.Contains("无法确认", rows[1].StatusLabel);
        Assert.Equal("探测超时", rows[1].Detail);
        Assert.Contains("无有效探测方式", rows[2].StatusLabel);
        Assert.Contains("推断", rows[3].StatusLabel);
    }

    [Fact]
    public void LegacyTcpOpenPortsStillRender()
    {
        using var doc = JsonDocument.Parse("""{"openPorts":[443]}""");
        var row = Assert.Single(ScanPortResult.FromToolResult(doc.RootElement, "tcp"));
        Assert.Equal(443, row.Port);
        Assert.Equal("open", row.State);
    }
}
