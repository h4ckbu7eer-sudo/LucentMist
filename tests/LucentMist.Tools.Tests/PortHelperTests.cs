using LucentMist.Tools.Common;

namespace LucentMist.Tools.Tests;

public class PortHelperTests
{
    [Fact]
    public void ParsePorts_MixedListAndRange_ReturnsSortedPorts()
    {
        var result = PortHelper.ParsePorts("80, 100-102, invalid, 443");

        Assert.Equal(new List<int> { 80, 100, 101, 102, 443 }, result);
    }

    [Fact]
    public void ParsePorts_RangeAboveUpperBound_ClampsAt65535()
    {
        var result = PortHelper.ParsePorts("65530-65540");

        Assert.Equal(new List<int> { 65530, 65531, 65532, 65533, 65534, 65535 }, result);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("100-1")]
    [InlineData("0")]
    [InlineData("65530-65540")]
    public void TryParsePorts_InvalidInput_ReturnsFalse(string input)
    {
        Assert.False(PortHelper.TryParsePorts(input, out var ports));
        Assert.Empty(ports);
    }

    [Fact]
    public void TryParsePorts_ValidInput_ReturnsSortedUniquePorts()
    {
        Assert.True(PortHelper.TryParsePorts("443,80-81,80", out var ports));
        Assert.Equal([80, 81, 443], ports);
    }

    [Fact]
    public void GetTcpServiceName_ReturnsKnownService()
    {
        Assert.Equal("HTTPS", PortHelper.GetTcpServiceName(443));
        Assert.Equal("MySQL", PortHelper.GetTcpServiceName(3306));
        Assert.Null(PortHelper.GetTcpServiceName(65534));
    }

    [Fact]
    public void GetUdpServiceName_ReturnsKnownService()
    {
        Assert.Equal("SNMP", PortHelper.GetUdpServiceName(161));
        Assert.Equal("NTP", PortHelper.GetUdpServiceName(123));
    }

    [Fact]
    public void GetServiceKey_ReturnsLowercaseServiceKey()
    {
        Assert.Equal("ssh", PortHelper.GetServiceKey(22));
        Assert.Equal("postgresql", PortHelper.GetServiceKey(5432));
    }
}
