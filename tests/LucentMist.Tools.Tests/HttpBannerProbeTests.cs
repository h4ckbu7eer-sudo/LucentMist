using System.Net;
using System.Net.Sockets;
using System.Text;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class HttpBannerProbeTests
{
    [Fact]
    public async Task HeadWithoutVersion_GetFallbackFindsServer_WithoutReadingBody()
    {
        var (result, requests) = await Probe(
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nSet-Cookie: not-product-evidence\r\n\r\n");
        Assert.StartsWith("HEAD /", requests[0]);
        Assert.StartsWith("GET /", requests[1]);
        Assert.Equal("version_observed", result.Status);
        Assert.Contains("nginx/1.24.0", result.Banner);
        Assert.DoesNotContain("not-product-evidence", result.Banner);
    }

    [Fact]
    public async Task CompletedHeadersWithoutVersion_AreNotProbeFailure_OrInventedCpe()
    {
        var (result, _) = await Probe(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal("version_not_disclosed", result.Status);
        Assert.Contains("HEAD/GET /", result.Reason);
        Assert.Null(ServiceFingerprint.FromBanner(result.Banner));
    }

    [Fact]
    public async Task TruncatedHeaders_AreFailure_NotNonDisclosure()
    {
        var (result, _) = await Probe("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", "garbage");
        Assert.Equal("probe_incomplete", result.Status);
        Assert.Contains("不能断言服务器未公开", result.Reason);
        Assert.Null(result.Banner);
    }

    [Fact]
    public void BodyCannotForgeServerHeader()
    {
        var banner = HttpBannerProbe.Parse("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: nginx/1.2.3\r\n");
        Assert.DoesNotContain("nginx", banner);
        Assert.Null(ServiceFingerprint.FromBanner(banner));
    }

    [Fact]
    public async Task CancellationStillPropagates()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            HttpBannerProbe.ProbeDetailedAsync("127.0.0.1", 80, 500, cancelled.Token));
    }

    private static async Task<(HttpBannerProbe.Result Result, List<string> Requests)> Probe(params string[] responses)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var requests = new List<string>();
        var server = Task.Run(async () =>
        {
            foreach (var response in responses)
            {
                using var client = await listener.AcceptTcpClientAsync(deadline.Token);
                using var stream = client.GetStream();
                var buffer = new byte[2048];
                var text = "";
                while (!text.Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var count = await stream.ReadAsync(buffer, deadline.Token);
                    if (count == 0) break;
                    text += Encoding.ASCII.GetString(buffer, 0, count);
                }
                requests.Add(text);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), deadline.Token);
            }
        }, deadline.Token);
        var result = await HttpBannerProbe.ProbeDetailedAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, 4000, deadline.Token);
        await server;
        return (result, requests);
    }
}
