using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class TrustAndPortPresentationTests
{
    [Fact]
    public void TlsGenericChainFailureDoesNotInventIncompleteChainOrSelfSignedLeaf()
    {
        Assert.DoesNotContain("不完整", TlsTrustLabels.Describe("ChainErrors"));
        Assert.Contains("链不完整", TlsTrustLabels.Describe("PartialChain"));
        Assert.Contains("不等于叶证书自签", TlsTrustLabels.Describe("UntrustedRoot"));
        Assert.Contains("不匹配", TlsTrustLabels.Describe("NameMismatch"));
    }

    [Fact]
    public async Task PortScanNonOpenIsNotClaimedClosed()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var result = await new PortScanTool(NullLogger<PortScanTool>.Instance).ExecuteAsync(new()
        { ["target"] = "127.0.0.1", ["ports"] = port.ToString(), ["timeout_ms"] = "100" });
        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal("closed_or_filtered_or_unreachable", doc.RootElement.GetProperty("nonOpenStatus").GetString());
        Assert.Contains("不等于关闭", doc.RootElement.GetProperty("nonOpenReason").GetString());
    }
}
