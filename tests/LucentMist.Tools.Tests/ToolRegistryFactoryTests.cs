using LucentMist.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class ToolRegistryFactoryTests
{
    [Fact]
    public void CreateDefault_RegistersAllLiveAgentTools()
    {
        var registry = ToolRegistryFactory.CreateDefault(NullLoggerFactory.Instance);

        var names = registry.ListAll()
            .Select(t => t.Name)
            .OrderBy(n => n)
            .ToArray();

        Assert.Equal(
            [
                "get_my_ip", "os_fingerprint", "ping_scan", "port_scan", "service_identify",
                "sirius_scan", "ssl_check", "udp_scan", "vuln_scan"
            ],
            names);
    }

    [Fact]
    public void CreateDefault_DoesNotExposeDeadDeviceTool()
    {
        var registry = ToolRegistryFactory.CreateDefault(NullLoggerFactory.Instance);

        Assert.Null(registry.Get("device_query"));
    }
}
