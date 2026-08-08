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
    public void EveryEntry_IsResolvableToCpe()
    {
        foreach (var entry in CpeCatalog.Entries)
            Assert.NotNull(CpeCatalog.GetCpe(entry.Key));
    }
}
