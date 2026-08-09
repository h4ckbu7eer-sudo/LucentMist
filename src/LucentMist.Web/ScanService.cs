using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging;

namespace LucentMist.Web;

public class ScanService
{
    private readonly PingScanTool _ping;
    private readonly PortScanTool _port;
    private readonly UdpScanTool _udp;
    private readonly ServiceIdentifyTool _service;
    private readonly SslCertificateTool _ssl;

    public ScanService(ILoggerFactory loggerFactory)
    {
        _ping = new PingScanTool(loggerFactory.CreateLogger<PingScanTool>());
        _port = new PortScanTool(loggerFactory.CreateLogger<PortScanTool>());
        _udp = new UdpScanTool(loggerFactory.CreateLogger<UdpScanTool>());
        _service = new ServiceIdentifyTool(loggerFactory.CreateLogger<ServiceIdentifyTool>());
        _ssl = new SslCertificateTool(loggerFactory.CreateLogger<SslCertificateTool>());
    }

    public async Task<object> PingScanAsync(string target)
    {
        var r = await _ping.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "2000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> PortScanAsync(string target, string ports)
    {
        var r = await _port.ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "2000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> UdpScanAsync(string target, string ports)
    {
        var r = await _udp.ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "3000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> ServiceIdentifyAsync(string target, int port)
    {
        var r = await _service.ExecuteAsync(new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "3000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    public async Task<object> SslCheckAsync(string target, int port = 443)
    {
        var r = await _ssl.ExecuteAsync(new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "5000" });
        return r.Success ? Parse(r.Data) : new { error = r.Error };
    }

    private static object Parse(string json)
    {
        try { return System.Text.Json.JsonSerializer.Deserialize<object>(json) ?? json; }
        catch { return json; }
    }
}
