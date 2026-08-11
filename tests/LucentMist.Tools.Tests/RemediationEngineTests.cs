using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class RemediationEngineTests
{
    [Theory]
    [InlineData("CVE-2017-0144", "smb")]
    [InlineData("CVE-2020-0796", "smb")]
    [InlineData("CVE-2023-38408", "ssh")]
    [InlineData("CVE-2023-44487", "http")]
    [InlineData("CVE-2024-21626", "docker")]
    [InlineData("CVE-2023-5157", "mysql")]
    [InlineData("CVE-2019-0708", "rdp")]
    [InlineData("CVE-2022-0543", "redis")]
    [InlineData("CVE-2021-44228", "http")]
    [InlineData("CVE-2018-15473", "ssh")]
    public void Generate_KnownCve_ReturnsSpecificRemediation(string cve, string service)
    {
        var result = new RemediationEngine().Generate("Windows", service, "1.0", cve);

        Assert.NotNull(result);
        Assert.NotEqual("通用", result!.Type);
        Assert.False(string.IsNullOrWhiteSpace(result.Description));
    }

    [Fact]
    public void Generate_LinuxKnownCve_DoesNotFallBackToGeneric()
    {
        var result = new RemediationEngine().Generate("Linux", "redis", "5.0.0", "CVE-2022-0543");

        Assert.NotNull(result);
        Assert.Equal("升级", result!.Type);
    }
}
