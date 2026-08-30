using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using LucentMist.Tools.Sirius;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools;

public static class ToolRegistryFactory
{
    public static ToolRegistry CreateDefault(ILoggerFactory loggerFactory)
    {
        var registry = new ToolRegistry();
        registry.Register(new GetMyIpTool());
        registry.Register(new PingScanTool(loggerFactory.CreateLogger<PingScanTool>()));
        registry.Register(new PortScanTool(loggerFactory.CreateLogger<PortScanTool>()));
        registry.Register(new ServiceIdentifyTool(loggerFactory.CreateLogger<ServiceIdentifyTool>()));
        registry.Register(new OsFingerprintTool(loggerFactory.CreateLogger<OsFingerprintTool>()));
        registry.Register(new SslCertificateTool(loggerFactory.CreateLogger<SslCertificateTool>()));
        registry.Register(new UdpScanTool(loggerFactory.CreateLogger<UdpScanTool>()));
        registry.Register(new VulnerabilityScanTool(loggerFactory.CreateLogger<VulnerabilityScanTool>()));
        registry.Register(new SiriusTool());
        return registry;
    }
}
