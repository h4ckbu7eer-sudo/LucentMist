using LucentMist.CLI;

namespace LucentMist.Tools.Tests;

public sealed class CliLoggingTests
{
    [Fact]
    public void ParseInvocation_DefaultsToNonVerboseAgentArguments()
    {
        var invocation = CliApp.ParseInvocation(["agent", "扫描 127.0.0.1"]);

        Assert.Equal("agent", invocation.Command);
        Assert.Equal(["扫描 127.0.0.1"], invocation.Arguments);
        Assert.False(invocation.Verbose);
    }

    [Theory]
    [InlineData("--verbose")]
    [InlineData("-v")]
    public void ParseInvocation_AcceptsVerboseBeforeCommand(string flag)
    {
        var invocation = CliApp.ParseInvocation([flag, "agent", "分析网络"]);

        Assert.Equal("agent", invocation.Command);
        Assert.Equal(["分析网络"], invocation.Arguments);
        Assert.True(invocation.Verbose);
    }

    [Fact]
    public void ParseInvocation_PreservesScanVerboseDisplayMode()
    {
        var invocation = CliApp.ParseInvocation(["--verbose", "scan", "127.0.0.1", "--ports", "80"]);

        Assert.Equal("scan", invocation.Command);
        Assert.Contains("--verbose", invocation.Arguments);
        Assert.True(invocation.Verbose);
    }
}
