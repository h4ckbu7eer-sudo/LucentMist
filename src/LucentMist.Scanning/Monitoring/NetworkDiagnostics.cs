using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Scanning.Monitoring;

public sealed record DiagnosticCheck(string Layer, string Status, string Evidence);
public sealed record DiagnosticReport(DiagnosticCheck[] Checks, string[] Suggestions);

public sealed class NetworkDiagnostics
{
    private readonly Func<List<LocalNetworkEntry>> _interfaces;
    private readonly Func<string, CancellationToken, Task<bool>> _gateway;
    private readonly Func<string, CancellationToken, Task<bool>> _dns;
    private readonly Func<CancellationToken, Task<bool>> _internet;
    private readonly Func<string[]> _listeners;
    public NetworkDiagnostics(Func<List<LocalNetworkEntry>>? interfaces = null,
        Func<string, CancellationToken, Task<bool>>? gateway = null,
        Func<string, CancellationToken, Task<bool>>? dns = null,
        Func<CancellationToken, Task<bool>>? internet = null, Func<string[]>? listeners = null)
    {
        _interfaces = interfaces ?? LocalNetworkInfo.GetEntries;
        _gateway = gateway ?? ProbeGateway;
        _dns = dns ?? (async (name, ct) => (await Dns.GetHostAddressesAsync(name, ct)).Length > 0);
        _internet = internet ?? ProbeInternet;
        _listeners = listeners ?? (() => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
            .Select(endpoint => endpoint.ToString()).Distinct().Order().ToArray());
    }

    public async Task<DiagnosticReport> RunAsync(string? gatewayOverride = null, string dnsName = "example.com", bool external = true, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        LocalNetworkEntry? primary = null;
        try { primary = LocalNetworkInfo.GetPrimaryInterface(_interfaces()); }
        catch (NetworkInformationException) { }
        var gateway = gatewayOverride ?? primary?.Gateway;
        var checks = new List<DiagnosticCheck>
        {
            new("interface", primary == null ? "warning" : "ok", primary == null ? "未取得启用的物理主接口；请检查网卡/Wi-Fi/VPN" : $"{primary.Name}: {primary.Ip}/{primary.Prefix}"),
        };
        var gatewayTask = IPAddress.TryParse(gateway, out _) ? Probe("gateway", gateway!, token => _gateway(gateway!, token), ct)
            : Task.FromResult(new DiagnosticCheck("gateway", "skipped", "未取得网关 IP；可用 --gateway 明确指定局域网网关"));
        var dnsTask = Probe("dns", $"本机解析器查询 {dnsName}（可能命中缓存）", token => _dns(dnsName, token), ct);
        var internetTask = external ? Probe("internet", "TCP 1.1.1.1:443（单一出口检查，不代表所有互联网服务）", _internet, ct)
            : Task.FromResult(new DiagnosticCheck("internet", "skipped", "已使用 --no-external，不访问公网测试端点"));
        checks.AddRange(await Task.WhenAll(gatewayTask, dnsTask, internetTask));
        try
        {
            var ports = _listeners();
            checks.Add(new("listeners", "ok", ports.Length == 0 ? "本机未取得 TCP 监听端口" :
                $"本机 TCP 监听 {ports.Length} 项（不等于公网暴露）：" + string.Join(", ", ports.Take(64)) + (ports.Length > 64 ? "；仅列前 64 项" : "")));
        }
        catch (Exception ex) when (ex is NetworkInformationException or UnauthorizedAccessException)
        { checks.Add(new("listeners", "warning", "无法读取本机监听端口，可能需要权限；不代表没有监听服务")); }
        return new(checks.ToArray(), Explain(checks));
    }

    public static string[] Explain(IEnumerable<DiagnosticCheck> input)
    {
        var checks = input.ToDictionary(c => c.Layer);
        bool Is(string layer, string status) => checks.TryGetValue(layer, out var check) && check.Status == status;
        var advice = new List<string>();
        if (!Is("interface", "ok")) advice.Add("先检查 Wi-Fi/网线、网卡是否启用和是否取得地址；虚拟/VPN 网络需核对实际路由，不能仅据主接口缺失断言断网。");
        if (Is("dns", "failed") && Is("internet", "ok")) advice.Add("公网 TCP 可达但 DNS 解析失败：优先检查本机 DNS 设置/解析缓存；不能登录路由器时联系管理员核对路由器 DNS。");
        else if (Is("dns", "failed")) advice.Add("本机域名解析未成功；可能是 DNS、联网或该域名问题，换一个已知域名复查后再调整本机 DNS。");
        if (Is("gateway", "failed") && Is("internet", "ok")) advice.Add("外网 TCP 可达：网关可能只是不响应 ICMP/TCP 探测，不能断言网关掉线。");
        else if (Is("gateway", "failed")) advice.Add("网关探测未成功：检查当前网段、Wi-Fi连接与路由；睡眠/防火墙拒绝也会造成无响应。");
        if (Is("internet", "failed")) advice.Add(Is("gateway", "ok")
            ? "网关可达，但 1.1.1.1:443 不通：可能是上联网路、该端点被拦截或代理策略；用浏览器访问另一站点交叉验证，不能据单个端点判整个互联网断网。"
            : "外网测试端点未连接成功，结合接口和网关结果排查；不把单端点失败直接当作运营商故障。");
        if (advice.Count == 0) advice.Add("本次已执行的基础检查未发现明确断点；这不是网速、丢包、Wi-Fi质量或漏洞安全的全面保证。");
        advice.Add("本工具只监控、告警和给出建议，不会下发路由规则、隔离设备或自动修复；无路由器管理权限时需手动处理或联系管理员。");
        return advice.ToArray();
    }

    private static async Task<DiagnosticCheck> Probe(string layer, string evidence, Func<CancellationToken, Task<bool>> run, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(6));
        try { return new(layer, await run(timeout.Token) ? "ok" : "failed", evidence); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ArgumentException or NetworkInformationException or JsonException)
        { return new(layer, "failed", evidence + "；未取得成功结果（失败/超时），不是确定故障原因"); }
    }
    private static async Task<bool> ProbeGateway(string target, CancellationToken ct)
    {
        var scope = MonitorScope.Create(target, "443"); // Gateway checks stay inside the home scope.
        var result = await new PingScanTool(NullLogger<PingScanTool>.Instance).ExecuteAsync(new() { ["target"] = scope.Subnet, ["timeout_ms"] = "800" }, ct);
        if (!result.Success) return false;
        using var data = JsonDocument.Parse(result.Data);
        return data.RootElement.GetProperty("alive").GetInt32() > 0;
    }
    private static async Task<bool> ProbeInternet(CancellationToken ct)
    {
        // This fixed endpoint is a documented connectivity check, not arbitrary public port scanning.
        var target = await TargetGuard.ValidateAsync("1.1.1.1", ct);
        if (!target.IsAllowed) return false;
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Parse("1.1.1.1"), 443, ct);
        return socket.Connected;
    }
}
