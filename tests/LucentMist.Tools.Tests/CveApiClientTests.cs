using System.Net;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class CveApiClientTests
{
    [Fact]
    public async Task TryOsvSearch_OpenSshBanner_UsesUpstreamTagAndMarksHitVerified()
    {
        string? requestBody = null;
        using var client = new HttpClient(new StubHandler(async request =>
        {
            requestBody = await request.Content!.ReadAsStringAsync();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"vulns":[{"aliases":["CVE-2099-0001"],"summary":"version match"}]}""",
                    Encoding.UTF8,
                    "application/json")
            };
        }));

        var results = await CveApiClient.TryOsvSearch(
            "ssh",
            "SSH-2.0-OpenSSH_9.8p1 Ubuntu",
            client,
            CancellationToken.None);

        var result = Assert.Single(results!);
        Assert.Equal("verified", result.VersionStatus);
        Assert.Contains("版本命中", result.VerificationDetail);
        using var request = JsonDocument.Parse(requestBody!);
        Assert.Equal("GIT", request.RootElement.GetProperty("package").GetProperty("ecosystem").GetString());
        Assert.Equal(
            "https://github.com/openssh/openssh-portable.git",
            request.RootElement.GetProperty("package").GetProperty("name").GetString());
        Assert.Equal("V_9_8_P1", request.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public void CreateOsvQuery_DoesNotInventDebianVersionForGenericBanner()
    {
        Assert.Null(CveApiClient.CreateOsvQuery("redis", "Redis 6.0.16"));
    }

    private sealed class StubHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => responseFactory(request);
    }
}
