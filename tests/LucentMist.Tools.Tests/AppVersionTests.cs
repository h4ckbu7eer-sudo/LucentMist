using LucentMist.Core;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class AppVersionTests
{
    [Fact]
    public void SharedAssemblies_UseCentralizedVersion()
    {
        var coreVersion = typeof(AppVersion).Assembly.GetName().Version?.ToString(3);
        var toolsVersion = typeof(CveDatabase).Assembly.GetName().Version?.ToString(3);

        Assert.Equal(coreVersion, toolsVersion);
    }
}
