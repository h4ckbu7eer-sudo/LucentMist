using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class CpeCatalogTests
{
    [Theory]
    [InlineData("smb")]
    [InlineData("ssh")]
    [InlineData("openssh")]
    [InlineData("http")]
    [InlineData("https")]
    [InlineData("mysql")]
    [InlineData("redis")]
    [InlineData("rdp")]
    [InlineData("apache")]
    [InlineData("tomcat")]
    [InlineData("k8s")]
    [InlineData("netbios-ssn")]
    [InlineData("mssql")]
    [InlineData("sqlserver")]
    public void ServiceMapping_And_Matcher_Agree(string service)
    {
        var direct = ServiceCpeMapping.GetCpe(service);
        var matched = new CpeMatcher().Match(service, "*")?.Cpe;

        Assert.NotNull(direct);
        Assert.NotNull(matched);
        Assert.Equal(direct, matched);
    }

    [Fact]
    public void Entries_HaveNoDuplicateKeys()
    {
        var duplicates = CpeCatalog.Entries
            .GroupBy(e => e.Key)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToArray();

        Assert.Empty(duplicates);
    }

    [Fact]
    public void Match_HttpAlt_DoesNotMatchNginx()
    {
        Assert.Null(new CpeMatcher().Match("http-alt", "*"));
    }

    [Fact]
    public void Match_Openssh_DoesNotMatchViaSshSubstring()
    {
        var matched = new CpeMatcher().Match("openssh", "9.6p1");

        Assert.NotNull(matched);
        Assert.Equal("openssh", matched!.Product);
    }

    [Fact]
    public void DetectOsFromTtl_MatchesOsFingerprintTool()
    {
        var matcher = new CpeMatcher();

        Assert.Equal(
            OsFingerprintTool.InferOs(true, 62, []).os,
            matcher.DetectOsFromTtl(62));
        Assert.Equal(
            OsFingerprintTool.InferOs(true, 128, []).os,
            matcher.DetectOsFromTtl(128));
    }

    [Fact]
    public void EveryEntry_IsResolvableToCpe()
    {
        foreach (var entry in CpeCatalog.Entries)
            Assert.NotNull(CpeCatalog.GetCpe(entry.Key));
    }

    [Fact]
    public void GetCpeAndKeyword_DeriveFromEntries()
    {
        foreach (var entry in CpeCatalog.Entries)
        {
            var cpe = CpeCatalog.GetCpe(entry.Key);
            var keyword = CpeCatalog.GetKeyword(entry.Key);

            Assert.NotNull(cpe);
            Assert.Contains(entry.Product, cpe);
            Assert.Equal(entry.Keyword, keyword);
        }
    }
}
