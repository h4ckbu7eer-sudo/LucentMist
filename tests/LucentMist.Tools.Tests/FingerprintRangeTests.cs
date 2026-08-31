using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class FingerprintRangeTests
{
    [Theory]
    [InlineData("HTTP/1.1 200 OK", null, null)]
    [InlineData("DNS（版本未公开）", null, null)]
    [InlineData("SSH-2.0", null, null)]
    [InlineData("HTTP Server: nginx/1.24.0", "nginx", "1.24.0")]
    [InlineData("HTTP/1.1 200 Server: Apache/2.4.49", "http_server", "2.4.49")]
    [InlineData("SSH-2.0-OpenSSH_9.8p1 Ubuntu", "openssh", "9.8p1")]
    [InlineData("OpenSSH_for_Windows_9.5.0.0", "openssh", "9.5.0.0")]
    [InlineData("Apache Tomcat/9.0.1", "tomcat", "9.0.1")]
    [InlineData("nginx/1.24.0-rc1", "nginx", null)]
    [InlineData("VMware Authentication Daemon Version 1.10", null, null)]
    [InlineData("VMware Authentication Daemon Version 1.0", null, null)]
    [InlineData("VMware ESXi 8.0", null, null)]
    [InlineData("VMware vCenter 8.0", null, null)]
    [InlineData("VMware Workstation/17.5.0", "vmware_workstation", "17.5.0")]
    public void Fingerprint_RequiresProductEvidence(string banner, string? product, string? version)
    {
        var fingerprint = ServiceFingerprint.FromBanner(banner);
        Assert.Equal(product, fingerprint?.Product);
        Assert.Equal(version, fingerprint?.Version);
        if (fingerprint != null) Assert.Equal(13, fingerprint.Cpe.Split(':').Length);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("https")]
    [InlineData("dns")]
    [InlineData("ssh")]
    [InlineData("smb")]
    [InlineData("ftp")]
    [InlineData("ngin")]
    [InlineData("vmware")]
    public void ProtocolOrFuzzyName_DoesNotInventVendor(string service) =>
        Assert.Null(new CpeMatcher().Match(service, "1.2.3"));

    [Fact]
    public void OpenSshCpe_PatchIsUpdateComponent_NotVersionSuffix()
    {
        var fingerprint = ServiceFingerprint.FromBanner("SSH-2.0-OpenSSH_9.3p2")!;
        Assert.Equal("9.3p2", fingerprint.Version);
        Assert.Equal("cpe:2.3:a:openbsd:openssh:9.3:p2:*:*:*:*:*:*", fingerprint.Cpe);
    }

    [Theory]
    [InlineData("8.4p1", false)]
    [InlineData("8.5p1", true)]
    [InlineData("9.7p1", true)]
    [InlineData("9.8p1", false)]
    [InlineData("9.8p1-rc1", false)]
    public void Range_BothBoundsAndUnsupportedVersions(string version, bool expected) =>
        Assert.Equal(expected, new AffectedVersionRange("8.5p1", "9.8p1").Contains(version));

    [Theory]
    [InlineData(80, "Apache/2.4.48", "CVE-2021-42013", false)]
    [InlineData(443, "Apache/2.4.49", "CVE-2021-42013", true)]
    [InlineData(8080, "Apache/2.4.50", "CVE-2021-42013", true)]
    [InlineData(80, "Apache/2.4.51", "CVE-2021-42013", false)]
    [InlineData(80, "nginx/1.20.0", "CVE-2021-23017", true)]
    [InlineData(80, "nginx/1.20.1", "CVE-2021-23017", false)]
    [InlineData(80, "nginx/0.6.17", "CVE-2021-23017", false)]
    [InlineData(22, "OpenSSH_8.4p1", "CVE-2024-6387", false)]
    [InlineData(22, "OpenSSH_8.5p1", "CVE-2024-6387", true)]
    [InlineData(22, "OpenSSH_9.8p1", "CVE-2024-6387", false)]
    public void Rules_DoNotMatchBeforeIntroductionOrAfterFix(int port, string banner, string cve, bool expected) =>
        Assert.Equal(expected, CveDatabase.Match(port, banner).Any(entry => entry.Cve == cve));
}
