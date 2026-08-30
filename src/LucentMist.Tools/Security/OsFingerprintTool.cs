using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Core.Networking;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Security;

/// <summary>
/// OS 指纹识别 — 通过 TTL、TCP 窗口、ICMP 特征推断目标操作系统
/// </summary>
public class OsFingerprintTool : INetworkTargetTool
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

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var timeout = args.GetInt("timeout_ms", 5000);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标 IP", sw.Elapsed);
        var resolvedTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
        if (resolvedTarget == null)
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
        target = resolvedTarget;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("OsFingerprint: {Target}", target);

            // 1. ICMP Ping → 获取 TTL
            var (reachable, ttl, pingMs) = await PingWithTtl(target, timeout, cancellationToken);

            // 2. 开放端口 → OS 提示
            var portHints = await ProbeKnownPorts(target, timeout, cancellationToken);

            // 3. 综合推断 OS
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
                portHints,
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation("OsFingerprint done: {Target} → {Os} ({Conf}%)", target, osFamily, confidence);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    private async Task<(bool reachable, int ttl, long ms)> PingWithTtl(
        string ip,
        int timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var ping = new Ping();
            var options = new PingOptions { Ttl = 128, DontFragment = true };
            var reply = await ping.SendPingAsync(ip, timeout, new byte[32], options).WaitAsync(cancellationToken);
            return (reply.Status == IPStatus.Success, reply.Options?.Ttl ?? 0, reply.RoundtripTime);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Ping with TTL options failed for {Ip}; retrying without options", ip);
            // Try without TTL options
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeout).WaitAsync(cancellationToken);
                return (reply.Status == IPStatus.Success, reply.Options?.Ttl ?? 0, reply.RoundtripTime);
            }
            catch (Exception fallbackEx)
            {
                _logger.LogDebug(fallbackEx, "Ping failed for {Ip}", ip);
                return (false, 0, 0);
            }
        }
    }

    private async Task<List<string>> ProbeKnownPorts(string ip, int timeout, CancellationToken cancellationToken)
    {
        var hints = new List<string>();
        foreach (var (port, hint) in PortOsHints)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeout / PortOsHints.Count);
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port, cts.Token);
                hints.Add(hint);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Known port probe failed for {Ip}:{Port}", ip, port);
            }
        }
        return hints;
    }

    internal static (string os, int confidence, string[] reasons) InferOs(
        bool reachable, int ttl, List<string> portHints)
    {
        var reasons = new List<string>();
        var scores = new Dictionary<string, int>();

        if (!reachable)
            return ("未知 (不可达)", 0, ["目标不可达"]);

        if (ttl <= 0)
            return ("未知 (无法获取 TTL)", 0, ["Ping 未返回 TTL"]);

        // 允许最多 64 跳衰减，保留所有可能的初始 TTL 作为候选
        var possibleInitialTtls = TtlMap.Keys
            .Where(initial => initial >= ttl && initial - ttl <= 64)
            .OrderBy(initial => initial)
            .ToArray();

        if (possibleInitialTtls.Length == 0)
        {
            return ("未知", 0, ["TTL 不在已知初始值范围内"]);
        }

        var initialTtl = possibleInitialTtls[0];
        if (possibleInitialTtls.Length > 1)
            reasons.Add($"TTL={ttl}，可能初始值为 {string.Join("/", possibleInitialTtls)}，无法确认实际跳数");
        else
            reasons.Add($"TTL={ttl} (初始≈{initialTtl})");

        foreach (var possibleInitial in possibleInitialTtls)
        {
            if (TtlMap.TryGetValue(possibleInitial, out var candidates))
            {
                foreach (var os in candidates)
                    scores[os] = scores.GetValueOrDefault(os) + 20;
            }
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
            reasons.Add("低置信度：仅 TTL 推断，未考虑网络跳数衰减");
            // Default to most common for that TTL
            if (initialTtl == 128) scores["Windows"] = scores.GetValueOrDefault("Windows") + 10;
            if (initialTtl == 64) scores["Linux"] = scores.GetValueOrDefault("Linux") + 10;
        }

        if (scores.Count == 0)
            return ("未知", 10, reasons.ToArray());

        var best = scores.OrderByDescending(kv => kv.Value).First();
        var confidence = portHints.Count == 0
            ? Math.Min(45, best.Value)
            : Math.Min(90, best.Value);
        if (possibleInitialTtls.Length > 1)
        {
            reasons.Add("低置信度：TTL 跳数不确定，结果应视为参考");
            confidence = Math.Min(confidence, 60);
        }
        return (best.Key, confidence, reasons.ToArray());
    }
}
