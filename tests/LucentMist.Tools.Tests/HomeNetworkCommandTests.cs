using LucentMist.CLI;
using LucentMist.Scanning.Monitoring;

namespace LucentMist.Tools.Tests;

public class HomeNetworkCommandTests
{
    [Fact]
    public void MonitorArgumentsSupportEqualsAndSeparateValues()
    {
        var args = HomeNetworkCommands.Parse(["--interval=30", "--subnet", "192.168.99.0/24", "--once"], ["--once"], ["--interval", "--subnet"]);
        Assert.Equal("30", args["--interval"]);
        Assert.Equal("192.168.99.0/24", args["--subnet"]);
        Assert.Equal("true", args["--once"]);
    }

    [Theory]
    [InlineData("--interval")]
    [InlineData("--interval=")]
    [InlineData("--interva=1")]
    [InlineData("--once=false")]
    public void InvalidArgumentsAreNotSilentlyIgnored(string arg) =>
        Assert.Throws<ArgumentException>(() => HomeNetworkCommands.Parse([arg], ["--once"], ["--interval"]));

    [Fact]
    public void FailedPortScanRetainedBaselineIsVisiblyHistorical()
    {
        var time = DateTimeOffset.UtcNow;
        var device = new KnownDevice(new("192.168.99.1", null, "ZTE", "router", [80]), time, time, true, PortsObservedAt: time);
        var output = HomeNetworkCommands.PortObservation(device);
        Assert.Contains("本次扫描失败，保留历史", output);
        Assert.Contains("80", output);
        Assert.Contains("观测于", output);
    }

    [Fact]
    public void UnconfirmedIdentityDoesNotDisplayCurrentResponseAsTrusted()
    {
        var time = DateTimeOffset.UtcNow;
        var device = new KnownDevice(new("192.168.99.1", "00:11:22:33:44:55", "ZTE", "router", [80]), time, time, true,
            Trusted: true, PortsObservedAt: time, IdentityConfirmed: false);
        Assert.Contains("信任不适用于当前响应", HomeNetworkCommands.IdentityObservation(device));
        Assert.DoesNotContain("/可信", HomeNetworkCommands.IdentityObservation(device));
        Assert.Contains("身份未确认，保留历史", HomeNetworkCommands.PortObservation(device));
    }

    [Theory]
    [InlineData("192.168.99.0/24")]
    [InlineData("1.1.1.1")]
    [InlineData("::1")]
    public void InvalidGatewayIsNotSilentlySkippedAsASuccessfulDiagnosis(string gateway) =>
        Assert.Throws<ArgumentException>(() => HomeNetworkCommands.ValidateGateway(gateway));
}
