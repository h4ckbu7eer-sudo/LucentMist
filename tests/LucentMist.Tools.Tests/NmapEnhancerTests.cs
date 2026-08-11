using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class NmapEnhancerTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("scanme.nmap.org")]
    [InlineData("example.com")]
    public void IsValidTarget_AcceptsIpAndHostname(string target)
    {
        Assert.True(NmapEnhancer.IsValidTarget(target));
    }

    [Theory]
    [InlineData("")]
    [InlineData("example.com; rm -rf /")]
    [InlineData("-oX /tmp/evil")]
    [InlineData("foo bar")]
    public void IsValidTarget_RejectsUnsafeInput(string target)
    {
        Assert.False(NmapEnhancer.IsValidTarget(target));
    }
}
