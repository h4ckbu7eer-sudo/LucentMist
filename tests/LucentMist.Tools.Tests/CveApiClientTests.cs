using System.Net;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class CveApiClientTests
{
    [Fact]
    public void ConsultedSources_WithVersionEvidence_ListsEveryQueriedSource()
    {
        var sources = CveApiClient.GetConsultedSources(
            22,
            "SSH-2.0-OpenSSH_9.2p1",
            externalEnabled: true);

        Assert.Equal(new[] { "CVETodo API", "Shodan API", "NVD" }, sources);
    }

    [Fact]
    public void ConsultedSources_WithoutVersionEvidence_DoesNotClaimExternalCalls()
    {
        Assert.Empty(CveApiClient.GetConsultedSources(
            22,
            "SSH（版本未知）",
            externalEnabled: true));
    }
    [Fact]
    public async Task TryOsvSearch_BannerOnlyEvidence_DoesNotCallOsvOrClaimVerification()
    {
        var calls = 0;
        using var client = new HttpClient(new StubHandler(request =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }));

        var results = await CveApiClient.TryOsvSearch(
            "SSH-2.0-OpenSSH_9.8p1 Ubuntu",
            client,
            CancellationToken.None);

        Assert.Null(results);
        Assert.Equal(0, calls);
        Assert.Null(CveApiClient.CreateOsvCommitQuery("SSH-2.0-OpenSSH_9.8p1 Ubuntu"));
    }

    [Fact]
    public async Task TryOsvSearch_ExplicitCommit_UsesOfficialCommitContract()
    {
        const string commit = "6879efc2c1596d11a6a6ad296f80063b558d5e0f";
        string? requestBody = null;
        using var client = new HttpClient(new StubHandler(async request =>
        {
            requestBody = await request.Content!.ReadAsStringAsync();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"vulns":[]}""",
                    Encoding.UTF8,
                    "application/json")
            };
        }));

        var results = await CveApiClient.TryOsvSearch(
            $"OpenSSH_9.8p1 commit={commit}",
            client,
            CancellationToken.None);

        Assert.Empty(results!);
        using var request = JsonDocument.Parse(requestBody!);
        Assert.Equal(commit, request.RootElement.GetProperty("commit").GetString());
        Assert.False(request.RootElement.TryGetProperty("package", out _));
        Assert.False(request.RootElement.TryGetProperty("version", out _));
    }

    [Fact]
    public void MergeSourceDetails_KeepsVersionEvidenceAndBestCvssMetadata()
    {
        var merged = CveApiClient.MergeSourceDetails(new[]
        {
            new CveApiClient.CveDetail(
                "CVE-2099-0003", "OSV summary", 0, "OSV.dev", "upgrade",
                "verified", "OSV commit match"),
            new CveApiClient.CveDetail(
                "CVE-2099-0003", "NVD description", 8.1, "NVD", "vendor fix")
        });

        Assert.Equal("verified", merged.VersionStatus);
        Assert.Equal("OSV commit match", merged.VerificationDetail);
        Assert.Equal(8.1, merged.CvssScore);
        Assert.Equal("NVD description", merged.Description);
        Assert.Contains("OSV.dev", merged.Source);
        Assert.Contains("NVD", merged.Source);
    }

    private sealed class StubHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => responseFactory(request);
    }
}
