using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Security;

/// <summary>
/// OS 指纹识别 — 通过 TTL、TCP 窗口、ICMP 特征推断目标操作系统
/// </summary>
public class OsFingerprintTool : ITool
{
    private readonly ILogger<OsFingerprintTool> _logger;

    public string Name => "os_fingerprint";
    public string Description => "识别目标 IP 的操作系统类型，通过 TTL/TCP/ICMP 特征推断";
    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标 IP", Required = true },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "5000" }
    ];

    // TTL → OS 映射（初始 TTL）
    private static readonly Dictionary<int, string[]> TtlMap = new()
    {
        [128] = ["Windows", "Windows Server"],
        [255] = ["Solaris", "AIX", "Cisco IOS"],
        [64] = ["Linux", "macOS", "FreeBSD", "Android", "OpenWrt"],
        [32] = ["Windows 95/98"],
        [60] = ["AIX"],
        [200] = ["Windows 98"],
    };

    // 常见端口 → 可能 OS
    private static readonly Dictionary<int, string> PortOsHints = new()
    {
        [135] = "Windows (RPC)",
        [139] = "Windows (NetBIOS)",
        [445] = "Windows/Linux (SMB)",
        [3389] = "Windows (RDP)",
        [22] = "Linux/macOS (SSH)",
        [5353] = "Linux/macOS (mDNS)",
    };

    public OsFingerprintTool(ILogger<OsFingerprintTool>? logger = null)
    {
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<OsFingerprintTool>.Instance;
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var timeout = args.GetInt("timeout_ms", 5000);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标 IP", sw.Elapsed);

        try
        {
            _logger.LogInformation("OsFingerprint: {Target}", target);

            // 1. ICMP Ping → 获取 TTL
            var (reachable, ttl, pingMs) = await PingWithTtl(target, timeout);

            // 2. TCP 连接测试 → 获取窗口大小
            var tcpWindows = await ProbeTcpWindows(target, timeout);

            // 3. 开放端口 → OS 提示
            var portHints = await ProbeKnownPorts(target, timeout);

            // 4. 综合推断 OS
            var (osFamily, confidence, reasons) = InferOs(reachable, ttl, portHints);

            var result = new
            {
                target,
                reachable,
                osFamily,
                confidence,
                reasons,
                ttl,
                pingMs,
                tcpWindows,
                portHints,
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation("OsFingerprint done: {Target} → {Os} ({Conf}%)", target, osFamily, confidence);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (Exception ex)
        {
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    private async Task<(bool reachable, int ttl, long ms)> PingWithTtl(string ip, int timeout)
    {
        try
        {
            using var ping = new Ping();
            var options = new PingOptions { Ttl = 128, DontFragment = true };
            var reply = await ping.SendPingAsync(ip, timeout, new byte[32], options);
            return (reply.Status == IPStatus.Success, reply.Options?.Ttl ?? 0, reply.RoundtripTime);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Ping with TTL options failed for {Ip}; retrying without options", ip);
            // Try without TTL options
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeout);
                return (reply.Status == IPStatus.Success, reply.Options?.Ttl ?? 0, reply.RoundtripTime);
            }
            catch (Exception fallbackEx)
            {
                _logger.LogWarning(fallbackEx, "Ping failed for {Ip}", ip);
                return (false, 0, 0);
            }
        }
    }

    private async Task<Dictionary<int, int>> ProbeTcpWindows(string ip, int timeout)
    {
        var windows = new Dictionary<int, int>();
        var ports = new[] { 80, 443, 22, 445 };
        foreach (var port in ports)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeout / ports.Length);
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port, cts.Token);
                // ReceiveBufferSize 是本机 socket 配置，不是远端 TCP 窗口，仅供调试，不参与 OS 推断。
                windows[port] = client.ReceiveBufferSize;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TCP window probe failed for {Ip}:{Port}", ip, port);
            }
        }
        return windows;
    }

    private async Task<List<string>> ProbeKnownPorts(string ip, int timeout)
    {
        var hints = new List<string>();
        foreach (var (port, hint) in PortOsHints)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeout / PortOsHints.Count);
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port, cts.Token);
                hints.Add(hint);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Known port probe failed for {Ip}:{Port}", ip, port);
            }
        }
        return hints;
    }

    private static (string os, int confidence, string[] reasons) InferOs(
        bool reachable, int ttl, List<string> portHints)
    {
        var reasons = new List<string>();
        var scores = new Dictionary<string, int>();

        if (!reachable)
            return ("未知 (不可达)", 0, ["目标不可达"]);

        // TTL 推断
        int initialTtl;
        if (ttl <= 32) initialTtl = 32;
        else if (ttl <= 60) initialTtl = 60;
        else if (ttl <= 64) initialTtl = 64;
        else if (ttl <= 128) initialTtl = 128;
        else initialTtl = 255;

        reasons.Add($"TTL={ttl} (初始≈{initialTtl})");

        if (TtlMap.TryGetValue(initialTtl, out var candidates))
        {
            foreach (var os in candidates)
                scores[os] = scores.GetValueOrDefault(os) + 30;
        }

        // Port hints
        foreach (var hint in portHints)
        {
            reasons.Add($"开放端口提示: {hint}");
            if (hint.Contains("Windows")) { scores["Windows"] = scores.GetValueOrDefault("Windows") + 20; scores["Windows Server"] = scores.GetValueOrDefault("Windows Server") + 15; }
            if (hint.Contains("Linux")) { scores["Linux"] = scores.GetValueOrDefault("Linux") + 15; scores["Android"] = scores.GetValueOrDefault("Android") + 10; }
            if (hint.Contains("macOS")) { scores["macOS"] = scores.GetValueOrDefault("macOS") + 15; }
        }

        if (portHints.Count == 0)
        {
            reasons.Add("仅 TTL 推断（无额外特征）");
            // Default to most common for that TTL
            if (initialTtl == 128) scores["Windows"] = scores.GetValueOrDefault("Windows") + 10;
            if (initialTtl == 64) scores["Linux"] = scores.GetValueOrDefault("Linux") + 10;
        }

        if (scores.Count == 0)
            return ("未知", 10, reasons.ToArray());

        var best = scores.OrderByDescending(kv => kv.Value).First();
        var confidence = Math.Min(90, best.Value);
        return (best.Key, confidence, reasons.ToArray());
    }
}
