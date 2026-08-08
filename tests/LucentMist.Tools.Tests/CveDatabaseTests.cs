using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class CveDatabaseTests
{
    [Fact]
    public void Match_NullOrEmptyBanner_ReturnsEmpty()
    {
        Assert.Empty(CveDatabase.Match(445, null));
        Assert.Empty(CveDatabase.Match(445, ""));
        Assert.Empty(CveDatabase.Match(445, "   "));
    }

    [Fact]
    public void Match_OpenSshBanner_UsesProductVersionInsteadOfProtocolVersion()
    {
        var matches = CveDatabase.Match(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu");

        Assert.Contains(matches, e => e.Cve == "CVE-2023-38408");
        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2018-15473");
    }

    [Fact]
    public void Match_ModernOpenSsh_IsNotFlaggedAsOld()
    {
        var matches = CveDatabase.Match(22, "SSH-2.0-OpenSSH_9.6p1");

        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2023-38408");
    }
}
