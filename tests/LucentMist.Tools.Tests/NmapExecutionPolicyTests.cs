using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class NmapExecutionPolicyTests
{
    [Fact]
    public async Task NmapUnavailableIsExplicit_NotEmptySuccess()
    {
        var enhancer = new NmapEnhancer(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "nmap"));
        Assert.Empty(await enhancer.ScanManyAsync("127.0.0.1", [80]));
        Assert.Equal("unavailable", enhancer.LastExecution!.Status);
        Assert.Null(enhancer.LastExecution.ProcessId);
    }

}
