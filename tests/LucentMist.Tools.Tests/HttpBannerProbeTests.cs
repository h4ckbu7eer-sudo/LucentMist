using System.Net;
using System.Net.Sockets;
using System.Text;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class HttpBannerProbeTests
{
    [Fact]
    public async Task GeneratorVersionIsNotReportedAsUndisclosed()
    {
        const string body = "<meta name=\"generator\" content=\"WordPress 6.4.3\">";
        var (result, _) = await Probe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}");
        Assert.Equal("6.4.3", ServiceFingerprint.FromBanner(result.Banner)?.Version);
        Assert.Equal("version_observed", result.Status);
        Assert.Contains("Generator", result.Reason);
    }

    [Fact]
    public async Task HeadersBeyondFourKiBAreRead_ViaIsEvidenceNotOriginProduct()
    {
        var (result, _) = await Probe("HTTP/1.1 200 OK\r\nX-Padding: " + new string('a', 5000) +
            "\r\nServer: lighttpd/1.4.76\r\nVia: 1.1 nginx/1.0\r\nSet-Cookie: private-test-value\r\n\r\n");
        Assert.Equal("version_observed", result.Status);
        var response = Assert.Single(result.Responses);
        Assert.True(response.HeaderBytes > 4096);
        Assert.Equal("lighttpd/1.4.76", response.Server);
        Assert.Equal("1.1 nginx/1.0", response.Via);
        Assert.DoesNotContain("private-test-value", System.Text.Json.JsonSerializer.Serialize(result));
        Assert.Equal("lighttpd", ServiceFingerprint.FromBanner(result.Banner)?.ProductKey);
    }

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

    [Fact]
    public async Task GatewayWithoutServer_ExposesChineseTitleButNoInventedVersion()
    {
        const string body = "<html><title>中兴智能路由器</title><script>privateToken='do-not-save'</script></html>";
        var (result, _) = await Probe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}");
        Assert.Equal("中兴智能路由器", result.PageIdentity?.Title);
        Assert.Equal("ZTE", result.PageIdentity?.Vendor);
        Assert.Null(result.PageIdentity?.Model);
        Assert.Null(ServiceFingerprint.FromBanner(result.Banner));
        Assert.DoesNotContain("do-not-save", System.Text.Json.JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task ChunkedHtmlHasTitle_NoBodyForgedServerHeader()
    {
        const string body = "<title>Router</title>Server: nginx/1.2.3";
        var (result, _) = await Probe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            $"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body.Length:x}\r\n{body}\r\n0\r\n\r\n");
        Assert.Equal("Router", result.PageIdentity?.Title);
        Assert.Null(ServiceFingerprint.FromBanner(result.Banner));
    }

    [Fact]
    public async Task RedirectIsNotFollowedToAnotherTarget()
    {
        var (result, requests) = await Probe("HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/admin\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/admin\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal(2, requests.Count);
        Assert.All(requests, request => Assert.DoesNotContain("192.0.2.1", request));
        Assert.Null(result.PageIdentity?.Title);
        Assert.Equal("probe_incomplete", result.Status);
    }

    [Fact]
    public async Task ErrorPageTitleIsNotMistakenForDeviceName()
    {
        var (result, _) = await Probe("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 400 Bad Request\r\n\r\n<title>400 Bad Request</title>");
        Assert.Null(result.PageIdentity?.Title);
        Assert.Equal("probe_incomplete", result.Status);
    }

    [Fact]
    public async Task AnalysisScopeReusesSameHttpEvidence_WithoutProcessWideStaleness()
    {
        var calls = 0;
        Task<HttpBannerProbe.Result> Read() { calls++; return Task.FromResult(new HttpBannerProbe.Result(null, "unknown", "test")); }
        using (LucentMist.Tools.Discovery.HttpObservationScope.Begin())
        {
            await LucentMist.Tools.Discovery.HttpObservationScope.GetAsync("127.0.0.1", 80, Read, default);
            await LucentMist.Tools.Discovery.HttpObservationScope.GetAsync("127.0.0.1", 80, Read, default);
            Assert.Equal(1, calls);
        }
        await LucentMist.Tools.Discovery.HttpObservationScope.GetAsync("127.0.0.1", 80, Read, default);
        Assert.Equal(2, calls);
    }

    [Theory]
    [InlineData("Basic realm=\"ZXHN H108L\"", "ZTE", "ZXHN H108L")]
    [InlineData("Digest realm=\"cpe@zte.com\"", "ZTE", null)]
    [InlineData("Basic realm=\"ZXV10 W300\"", "ZTE", "ZXV10 W300")]
    public void RecogRealmRulesProvideExplicitDeviceIdentity_NotSoftwareVersion(string realm, string vendor, string? model)
    {
        var identity = LucentMist.Tools.Discovery.HttpPageIdentity.Read("", realm);
        Assert.Equal(vendor, identity.Vendor);
        Assert.Equal(model, identity.Model);
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
                await stream.WriteAsync(Encoding.UTF8.GetBytes(response), deadline.Token);
            }
        }, deadline.Token);
        var result = await HttpBannerProbe.ProbeDetailedAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, 4000, deadline.Token);
        await server;
        return (result, requests);
    }
}
