using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Web;

public class ScanService
{
    private static ILogger<T> L<T>() => NullLogger<T>.Instance;

    public async Task<object> PingScanAsync(string target)
    {
        var tool = new PingScanTool(L<PingScanTool>());
        var r = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "2000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> PortScanAsync(string target, string ports)
    {
        var tool = new PortScanTool(L<PortScanTool>());
        var r = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "2000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> UdpScanAsync(string target, string ports)
    {
        var tool = new UdpScanTool(L<UdpScanTool>());
        var r = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "3000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> ServiceIdentifyAsync(string target, int port)
    {
        var tool = new ServiceIdentifyTool(L<ServiceIdentifyTool>());
        var r = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "3000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> SslCheckAsync(string target, int port = 443)
    {
        var tool = new SslCertificateTool(L<SslCertificateTool>());
        var r = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "5000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    private static object Parse(string json)
    {
        try { return System.Text.Json.JsonSerializer.Deserialize<object>(json) ?? json; }
        catch { return json; }
    }
}
