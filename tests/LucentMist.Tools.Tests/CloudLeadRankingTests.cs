using System.Text.Json;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class CloudLeadRankingTests
{
    [Fact]
    public void AncientKeywordLeadsAreRetainedButNotPromoted_EvenWithManyReferences()
    {
        var items = new[]
        {
            JsonSerializer.SerializeToElement(new { port = 53, cve = "CVE-1999-0010", name = "DNS port 53", source = "NVD", cvss = 0.0, referenceCount = 1000, versionStatus = "unverified" }),
            JsonSerializer.SerializeToElement(new { port = 53, cve = "CVE-2024-1000", name = "DNS", source = "NVD", cvss = 7.5, referenceCount = 1, versionStatus = "unverified" }),
        };
        var ranked = CloudLeadRanking.Rank(items);
        Assert.Equal("CVE-2024-1000", ranked[0].GetProperty("cve").GetString());
        Assert.Equal(2, ranked.Length);
        var group = Assert.Single(CloudLeadRanking.Group(ranked));
        Assert.Equal(1, group.GetProperty("historicalCount").GetInt32());
        Assert.Equal(1, group.GetProperty("omittedCount").GetInt32());
        Assert.Single(group.GetProperty("leads").EnumerateArray());
        Assert.DoesNotContain("1999", group.GetProperty("leads").GetRawText());
    }

    [Fact]
    public void OldVersionVerifiedEvidenceIsNotHiddenBecauseOfAge()
    {
        var ranked = CloudLeadRanking.Rank([JsonSerializer.SerializeToElement(new
        {
            port = 53, cve = "CVE-1999-0010", name = "DNS", source = "version-aware", versionStatus = "verified",
        })]);
        Assert.Single(Assert.Single(CloudLeadRanking.Group(ranked)).GetProperty("leads").EnumerateArray());
    }

    [Fact]
    public void FortyLeads_RelevanceWinsOverRecencyAndGroupsAreBounded()
    {
        var candidates = Enumerable.Range(0, 40).Select(index => JsonSerializer.SerializeToElement(new
        {
            port = index % 3 == 0 ? 53 : index % 3 == 1 ? 80 : 443,
            cve = $"CVE-2026-{1000 + index}",
            name = "Unrelated software",
            banner = "HTTP Server: nginx/1.20.0",
            source = "NVD",
            cvss = 9.8,
            versionStatus = "unverified",
            referenceCount = 100,
        })).ToList();
        candidates[1] = JsonSerializer.SerializeToElement(new
        {
            port = 80,
            cve = "CVE-2021-23017",
            name = "nginx resolver HTTP port 80",
            banner = "HTTP Server: nginx/1.20.0",
            source = "CVETodo API",
            cvss = 7.7,
            versionStatus = "unverified",
            referenceCount = 1,
        });
        var ranked = CloudLeadRanking.Rank(candidates);
        Assert.Equal(40, ranked.Length);
        Assert.Equal("CVE-2021-23017", ranked[0].GetProperty("cve").GetString());
        Assert.Contains("已识别产品", ranked[0].GetProperty("relevanceReason").GetString());
        Assert.Equal("unverified", ranked[0].GetProperty("versionStatus").GetString());
        var groups = CloudLeadRanking.Group(ranked);
        Assert.Equal(new[] { 53, 80, 443 }, groups.Select(group => group.GetProperty("port").GetInt32()));
        Assert.All(groups, group =>
        {
            Assert.Equal(3, group.GetProperty("leads").GetArrayLength());
            Assert.Contains("固件", group.GetProperty("nextStep").GetString());
        });
        Assert.Equal(31, groups.Sum(group => group.GetProperty("omittedCount").GetInt32()));
    }

    [Fact]
    public void UnknownBanner_DoesNotInventProductRelevance_AndOrderIsStable()
    {
        var items = new[] { "CVE-2026-1002", "CVE-2026-1001" }.Select(cve => JsonSerializer.SerializeToElement(new
        {
            port = 80,
            cve,
            name = "A DNS client vulnerability",
            banner = "HTTP (无 Server 头)",
            source = "NVD",
        })).ToArray();
        var result = CloudLeadRanking.Rank(items);
        Assert.All(result, item => Assert.Equal(0, item.GetProperty("relevanceScore").GetInt32()));
        Assert.Equal("CVE-2026-1001", result[0].GetProperty("cve").GetString());
        Assert.Equal(result.Select(item => item.GetRawText()), CloudLeadRanking.Rank(items.Reverse()).Select(item => item.GetRawText()));
    }
}
