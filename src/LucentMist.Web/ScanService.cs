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

    public async Task<ScanServiceResult> PingScanAsync(string target, CancellationToken cancellationToken = default)
    {
        var r = await _ping.ExecuteAsync(
            new ToolArguments { ["target"] = target, ["timeout_ms"] = "2000" },
            cancellationToken);
        return r.Success
            ? ScanServiceResult.Ok(Parse(r.Data))
            : ScanServiceResult.Fail(r.Error ?? "Ping 扫描失败");
    }

    public async Task<ScanServiceResult> PortScanAsync(
        string target,
        string ports,
        CancellationToken cancellationToken = default)
    {
        var r = await _port.ExecuteAsync(
            new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "2000" },
            cancellationToken);
        return r.Success
            ? ScanServiceResult.Ok(Parse(r.Data))
            : ScanServiceResult.Fail(r.Error ?? "TCP 扫描失败");
    }

    public async Task<ScanServiceResult> UdpScanAsync(
        string target,
        string ports,
        CancellationToken cancellationToken = default)
    {
        var r = await _udp.ExecuteAsync(
            new ToolArguments { ["target"] = target, ["ports"] = ports, ["timeout_ms"] = "3000" },
            cancellationToken);
        return r.Success
            ? ScanServiceResult.Ok(Parse(r.Data))
            : ScanServiceResult.Fail(r.Error ?? "UDP 扫描失败");
    }

    public async Task<ScanServiceResult> ServiceIdentifyAsync(
        string target,
        int port,
        CancellationToken cancellationToken = default)
    {
        var r = await _service.ExecuteAsync(
            new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "3000" },
            cancellationToken);
        return r.Success
            ? ScanServiceResult.Ok(Parse(r.Data))
            : ScanServiceResult.Fail(r.Error ?? "服务识别失败");
    }

    public async Task<ScanServiceResult> SslCheckAsync(
        string target,
        int port = 443,
        CancellationToken cancellationToken = default)
    {
        var r = await _ssl.ExecuteAsync(
            new ToolArguments { ["target"] = target, ["port"] = port.ToString(), ["timeout_ms"] = "5000" },
            cancellationToken);
        return r.Success
            ? ScanServiceResult.Ok(Parse(r.Data))
            : ScanServiceResult.Fail(r.Error ?? "SSL 检查失败");
    }

    private static object Parse(string json)
    {
        try { return System.Text.Json.JsonSerializer.Deserialize<object>(json) ?? json; }
        catch { return json; }
    }

    public sealed record ScanServiceResult(bool Success, object? Data, string? Error)
    {
        public static ScanServiceResult Ok(object data) => new(true, data, null);
        public static ScanServiceResult Fail(string error) => new(false, null, error);
    }
}
