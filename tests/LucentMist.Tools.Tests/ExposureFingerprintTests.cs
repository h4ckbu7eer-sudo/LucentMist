using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class ExposureFingerprintTests
{
    [Fact]
    public void EmptyServerHeader_CannotConsumeNextHeaderAsProduct()
    {
        var banner = HttpBannerProbe.Parse("HTTP/1.1 200 OK\r\nServer: \r\nAccept-Ranges: bytes\r\n\r\n");
        Assert.Equal("HTTP (无 Server 头)", banner);
        Assert.DoesNotContain("Accept-Ranges", banner);
    }
    [Fact]
    public void ServerAndPoweredBy_AreReportedWithoutCookies()
    {
        var banner = HttpBannerProbe.Parse("HTTP/1.1 200 OK\r\nServer: nginx/1.20.0\r\nX-Powered-By: PHP\r\nSet-Cookie: TEST_SECRET\r\n\r\n");
        Assert.Contains("nginx/1.20.0", banner);
        Assert.DoesNotContain("TEST_SECRET", banner);
        Assert.Equal("information_disclosed", VulnerabilityScanTool.BuildExposureAssessment(443, banner)!.Status);
    }
    [Theory]
    [InlineData(3306)]
    [InlineData(27017)]
    public void DatabasePortAlone_DoesNotClaimUnauthorizedAccess(int port) =>
        Assert.Equal("not_checked", VulnerabilityScanTool.BuildExposureAssessment(port, "unknown")!.Status);
    [Fact]
    public void RedisInfo_MetadataAccessIsNotRceOrFullDataAccess()
    {
        var banner = VulnerabilityScanTool.ParseRedisInfo("$90\r\n# Server\r\nredis_version:6.2.6\r\nprocess_id:1234\r\n");
        Assert.DoesNotContain("1234", banner);
        Assert.Equal("metadata_exposed", VulnerabilityScanTool.BuildExposureAssessment(6379, banner)!.Status);
        Assert.Contains(CveDatabase.Match(6379, banner), item => item.Cve == "CVE-2022-24735");
        Assert.DoesNotContain(CveDatabase.Match(6379, "Redis 6.2.7"), item => item.Cve == "CVE-2022-24735");
        Assert.DoesNotContain(CveDatabase.Match(6379, "Redis 5.0.0"), item => item.Cve == "CVE-2022-24735");
        Assert.Equal("access_denied", VulnerabilityScanTool.BuildExposureAssessment(6379, VulnerabilityScanTool.ParseRedisInfo("-NOAUTH Authentication required\r\n"))!.Status);
    }
}
