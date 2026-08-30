using LucentMist.CLI;

namespace LucentMist.Tools.Tests;

public sealed class ScanCommandOptionTests
{
    [Fact]
    public void ShouldRunPing_DefaultsToTrue()
    {
        Assert.True(CliApp.ShouldRunPing(["127.0.0.1", "--ports", "80"]));
    }

    [Fact]
    public void ShouldRunPing_NoPingDisablesDiscoveryStage()
    {
        Assert.False(CliApp.ShouldRunPing(["127.0.0.1", "--ports", "80", "--no-ping"]));
    }
}
