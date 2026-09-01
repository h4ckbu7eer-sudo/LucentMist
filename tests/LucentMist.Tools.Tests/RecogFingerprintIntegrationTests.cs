using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class RecogFingerprintIntegrationTests
{
    [Fact]
    public void EmbeddedDataset_IsPinnedAndSubstantial()
    {
        Assert.Equal("d3d20938da9f5f1e442c2419fe6c30cd651b6878", ServiceFingerprintMatcher.UpstreamCommit);
        Assert.Equal(950, ServiceFingerprintMatcher.ImportedRuleCount);
        Assert.Equal(950, ServiceFingerprintMatcher.RunnableRuleCount);
    }

    [Theory]
    [InlineData("HTTP Server: nginx/1.24.0", "nginx", "1.24.0")]
    [InlineData("HTTP Server: Apache/2.4.57 (Unix)", "apache", "2.4.57")]
    [InlineData("HTTP Server: Microsoft-IIS/10.0", "iis", "10.0")]
    [InlineData("HTTP Server: Apache Tomcat/9.0.82", "tomcat", "9.0.82")]
    [InlineData("HTTP Server: SimpleHTTP/0.6 Python/3.12.8", "simplehttp", "0.6")]
    [InlineData("HTTP Server: SimpleHTTP/0.6; Python/3.12.8", "simplehttp", "0.6")]
    [InlineData("SSH-2.0-OpenSSH_9.3p2", "openssh", "9.3p2")]
    [InlineData("SSH-2.0-dropbear_2022.83", "dropbear", "2022.83")]
    [InlineData("220 mail.example ESMTP Postfix (3.8.4)", "postfix", "3.8.4")]
    [InlineData("220 ESMTP Exim 4.96 Thu, 16 Nov 2023 12:19:22 +0300", "exim", "4.96")]
    [InlineData("DNS 9.18.28", "bind", "9.18.28")]
    [InlineData("220 (vsFTPd 3.0.5)", "vsftpd", "3.0.5")]
    [InlineData("220 ProFTPD 1.3.8 Server ready.", "proftpd", "1.3.8")]
    [InlineData("MySQL 8.0.36", "mysql", "8.0.36")]
    public void OfficialRecogExamples_MapBannerToProductVersionAndCpe(
        string banner, string productKey, string version)
    {
        var fingerprint = ServiceFingerprint.FromBanner(banner);

        Assert.NotNull(fingerprint);
        Assert.Equal(productKey, fingerprint.ProductKey);
        Assert.Equal(version, fingerprint.Version);
        if (productKey != "simplehttp") Assert.NotNull(fingerprint.Cpe);
        Assert.StartsWith("Rapid7 Recog ", fingerprint.EvidenceSource);
    }

    [Theory]
    [InlineData("+OK Dovecot ready.", "dovecot")]
    [InlineData("* OK Dovecot ready.", "dovecot")]
    public void VersionlessRecogBanner_StillIdentifiesProduct(string banner, string productKey)
    {
        var fingerprint = ServiceFingerprint.FromBanner(banner);

        Assert.NotNull(fingerprint);
        Assert.Equal(productKey, fingerprint.ProductKey);
        Assert.Null(fingerprint.Version);
    }

    [Fact]
    public void RpcBanner_IsObservedServiceWithoutInventedVersionOrApplicationCpe()
    {
        var fingerprint = ServiceFingerprint.FromBanner("Microsoft Windows RPC");

        Assert.NotNull(fingerprint);
        Assert.Equal("windows-rpc", fingerprint.ProductKey);
        Assert.Null(fingerprint.Version);
        Assert.False(fingerprint.HasApplicationCpe);
        Assert.Null(fingerprint.Cpe);
        Assert.Contains("版本未公开", fingerprint.EvidenceDescription);
    }

    [Fact]
    public void MetaGenerator_IsProductEvidenceWhenHeadersHideServerVersion()
    {
        var fingerprint = ServiceFingerprint.FromBanner(
            "HTTP (无 Server 头); HTTP Generator: WordPress 6.4.3");

        Assert.NotNull(fingerprint);
        Assert.Equal("wordpress", fingerprint.ProductKey);
        Assert.Equal("6.4.3", fingerprint.Version);
        Assert.Equal("cpe:2.3:a:wordpress:wordpress:6.4.3:*:*:*:*:*:*:*", fingerprint.Cpe);
    }
}
