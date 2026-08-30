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

    [Theory]
    [InlineData("9.0p1")]
    [InlineData("9.1")]
    [InlineData("9.2p1")]
    [InlineData("9.3p1")]
    public void Match_OpenSshBefore93P2_IsFlaggedAsVulnerable(string version)
    {
        var matches = CveDatabase.Match(22, $"SSH-2.0-OpenSSH_{version}");

        Assert.Contains(matches, e => e.Cve == "CVE-2023-38408");
    }

    [Theory]
    [InlineData("9.3p2")]
    [InlineData("9.4")]
    public void Match_OpenSsh93P2OrNewer_IsNotFlagged(string version)
    {
        var matches = CveDatabase.Match(22, $"SSH-2.0-OpenSSH_{version}");

        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2023-38408");
    }

    [Fact]
    public void Match_OpenSshForWindows_UsesProductVersion()
    {
        var matches = CveDatabase.Match(22, "SSH-2.0-OpenSSH_for_Windows_8.1");

        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2018-15473");
    }

    [Fact]
    public void ExtractVersion_PreservesOpenSshPatchSuffix()
    {
        var version = CveDatabase.ExtractVersion("SSH-2.0-OpenSSH_9.8p1 Ubuntu");

        Assert.Equal("9.8p1", version);
    }

    [Fact]
    public void ExtractVersion_PreservesAllNumericComponents()
    {
        var version = CveDatabase.ExtractVersion("nginx/1.2.3.4");

        Assert.Equal("1.2.3.4", version);
    }

    [Fact]
    public void ExtractVersion_PreservesExactSmbDialect()
    {
        Assert.Equal("3.1.1", CveDatabase.ExtractVersion("SMBv3.1.1"));
    }

    [Theory]
    [InlineData(445, "SMBv3.1.1", true)]
    [InlineData(445, null, false)]
    [InlineData(22, "SSH-2.0-OpenSSH_9.8p1", true)]
    [InlineData(22, "SSH service", false)]
    public void HasVersionEvidence_RequiresARecognizedServiceVersion(
        int port,
        string? banner,
        bool expected)
    {
        Assert.Equal(expected, CveDatabase.HasVersionEvidence(port, banner));
    }

    [Fact]
    public void Match_SmbV3_IsNotEternalBlue()
    {
        var matches = CveDatabase.Match(445, "SMBv3.1.1");

        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2017-0144");
        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2020-0796");
    }

    [Fact]
    public void Match_SmbV1_IsNotSmbGhost()
    {
        var matches = CveDatabase.Match(445, "SMBv1 (NT LM 0.12)");

        Assert.DoesNotContain(matches, e => e.Cve == "CVE-2020-0796");
    }

    [Fact]
    public void SmbGhost_RemediationDisablesCompressionInsteadOfSuggestingSigning()
    {
        var entry = Assert.Single(CveDatabase.Entries, item => item.Cve == "CVE-2020-0796");

        Assert.Contains("KB4551762", entry.Fix);
        Assert.Contains("DisableCompression=1", entry.Fix);
        Assert.Contains("禁用 SMB 压缩", entry.Fix);
        Assert.Contains("445", entry.Fix);
        Assert.DoesNotContain("SMB 签名", entry.Fix);
    }

    [Fact]
    public void EternalBlue_RemediationCoversPatchProtocolRemovalAndNetworkRestriction()
    {
        var entry = Assert.Single(CveDatabase.Entries, item => item.Cve == "CVE-2017-0144");

        Assert.Contains("MS17-010", entry.Fix);
        Assert.Contains("禁用 SMBv1", entry.Fix);
        Assert.Contains("445", entry.Fix);
    }

    [Theory]
    [InlineData(2375, "Docker/24.0.8", "CVE-2024-21626")]
    [InlineData(3306, "MySQL 8.0.34", "CVE-2023-5157")]
    [InlineData(3389, "RDP 7.1", "CVE-2019-0708")]
    [InlineData(6379, "Redis 6.0.15", "CVE-2022-0543")]
    [InlineData(8080, "Java HTTP", "CVE-2021-44228")]
    public void Match_DoesNotInferComponentOrPatchVulnerabilityFromUnrelatedBanner(
        int port,
        string banner,
        string cve)
    {
        Assert.DoesNotContain(CveDatabase.Match(port, banner), e => e.Cve == cve);
    }
}
