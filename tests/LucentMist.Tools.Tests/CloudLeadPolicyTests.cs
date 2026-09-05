using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class CloudLeadPolicyTests
{
    [Theory]
    [InlineData(3.9, "2025-01-01", false)]
    [InlineData(4.0, "2018-12-31", false)]
    [InlineData(4.0, "2019-01-01", true)]
    [InlineData(9.8, null, false)]
    [InlineData(0, "2025-01-01", false)]
    public void LeadsRequirePublicationAndScoreEvidence(double cvss, string? publishedAt, bool visible)
    {
        var candidate = JsonSerializer.SerializeToElement(new
        { port = 80, cve = "CVE-2009-0177", name = "nginx", banner = "HTTP Server: nginx/1.24.0", cvss, publishedAt });
        var ranked = CloudLeadRanking.Rank([candidate]);
        Assert.Single(ranked); // Preserve raw evidence, including old CVE IDs with new publication dates.
        Assert.Equal(visible ? 1 : 0, Assert.Single(CloudLeadRanking.Group(ranked)).GetProperty("leads").GetArrayLength());
    }

    [Theory]
    [InlineData("published")]
    [InlineData("published_time")]
    [InlineData("published_at")]
    public void PublishedDateSurvivesSourceMerge(string field)
    {
        var value = JsonSerializer.SerializeToElement(new Dictionary<string, string> { [field] = "2024-03-02T00:00:00Z" });
        var date = CveApiClient.ReadPublishedAt(value);
        Assert.Equal(2024, date!.Value.Year);
        var merged = CveApiClient.MergeSourceDetails([
            new("CVE-2024-1000", "nginx", 7, "NVD", "fix", PublishedAt: date),
            new("CVE-2024-1000", "nginx", 7, "Shodan", "fix")]);
        Assert.Equal(date, merged.PublishedAt);
    }

}
