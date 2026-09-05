using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Vulnerability;
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
        new() { Name = "open_ports", Type = "string", Description = "复用已发现的开放端口；空字符串表示已扫描且无开放端口", Required = false },
        new() { Name = "use_nmap", Type = "string", Description = "显式设为 true 才用 Nmap 服务证据辅助 OS 判断；也可设置 LMIST_USE_NMAP=true。默认关闭", Required = false, Default = "false" },
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
        var timeout = Math.Clamp(args.GetInt("timeout_ms", 5000), 100, 10000);

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

            if (IsLocalTarget(target))
            {
                var device = await DeviceDiscovery.EnrichAsync(target, cancellationToken);
                var localFamily = OperatingSystem.IsWindows() ? "Windows" :
                    OperatingSystem.IsLinux() ? "Linux" :
                    OperatingSystem.IsMacOS() ? "macOS" :
                    OperatingSystem.IsFreeBSD() ? "FreeBSD" : "未知";
                var localResult = new
                {
                    target,
                    reachable = true,
                    icmpReachable = true,
                    osFamily = localFamily,
                    osVersion = RuntimeInformation.OSDescription,
                    device,
                    confidence = 100,
                    evidenceType = "local_runtime",
                    limitation = "目标与本机接口精确匹配；这是本机运行时证据。它不能替代远程主机的主动 OS 指纹。",
                    reasons = new[] { "目标 IP 与本机启用接口匹配", $"运行时平台：{RuntimeInformation.OSDescription}" },
                    ttl = 0,
                    pingMs = 0L,
                    portHints = Array.Empty<string>(),
                    scanDuration = sw.Elapsed.ToString()
                };
                return ToolResult.Ok(JsonSerializer.Serialize(localResult), sw.Elapsed);
            }

            // 1. ICMP Ping → 获取 TTL
            var (reachable, ttl, pingMs) = await PingWithTtl(target, timeout, cancellationToken);

            // 2. 开放端口 → OS 提示
            var knownPorts = args.ContainsKey("open_ports") ? PortHelper.ParsePorts(args.GetOrDefault("open_ports")) : null;
            var portHints = knownPorts != null
                ? HintsFromPorts(knownPorts)
                : await ProbeKnownPorts(target, timeout, cancellationToken);
            var tcpReachable = knownPorts?.Count > 0 || portHints.Count > 0;

            if (knownPorts is { Count: > 0 } && VulnerabilityScanTool.ShouldUseNmap(args))
            {
                var nmap = new NmapEnhancer(timeoutSeconds: 15);
                if (nmap.IsAvailable)
                {
                    var nmapEvidence = await nmap.ScanManyAsync(target, knownPorts, cancellationToken);
                    var osTypes = nmapEvidence.Values
                        .Where(item => !string.IsNullOrWhiteSpace(item.OsType))
                        .OrderByDescending(item => item.Confidence)
                        .ToArray();
                    if (osTypes.Length > 0)
                    {
                        var best = osTypes[0];
                        var nmapResult = new
                        {
                            target,
                            reachable = true,
                            icmpReachable = reachable,
                            osFamily = best.OsType,
                            confidence = Math.Clamp(best.Confidence * 10, 60, 95),
                            evidenceType = "nmap_service",
                            limitation = "OS 来自 Nmap 服务指纹（产品/CPE/ostype），不是完整 TCP/IP OS 扫描；可确认平台家族线索，不能确认具体系统版本。",
                            reasons = nmapEvidence.Values.Where(item => !string.IsNullOrWhiteSpace(item.OsType))
                                .Select(item => $"端口 {item.Port}: {item.Product ?? item.ServiceName}; ostype={item.OsType}; conf={item.Confidence}").ToArray(),
                            ttl,
                            pingMs,
                            portHints,
                            scanDuration = sw.Elapsed.ToString()
                        };
                        return ToolResult.Ok(JsonSerializer.Serialize(nmapResult), sw.Elapsed);
                    }
                }
            }

            // 3. 综合推断 OS
            var (osFamily, confidence, reasons) = InferOs(reachable || tcpReachable, ttl, portHints);

            var result = new
            {
                target,
                reachable = reachable || tcpReachable,
                icmpReachable = reachable,
                osFamily,
                confidence,
                evidenceType = "heuristic",
                limitation = "TTL/端口仅提供低置信度 OS 线索，不是设备型号或确定 OS；不能据此排除另一平台的漏洞。",
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
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
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
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
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Known port probe failed for {Ip}:{Port}", ip, port);
            }
        }
        return hints;
    }

    internal static List<string> HintsFromPorts(IEnumerable<int> ports) => ports.Distinct()
        .Where(PortOsHints.ContainsKey).Select(port => PortOsHints[port]).ToList();

    internal static (string os, int confidence, string[] reasons) InferOs(
        bool reachable, int ttl, List<string> portHints)
    {
        var reasons = new List<string>();
        var scores = new Dictionary<string, int>();

        if (!reachable && portHints.Count == 0)
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
                    scores[os] = scores.GetValueOrDefault(os) + 25;
            }
        }

        // Port hints
        foreach (var hint in portHints.Distinct())
        {
            reasons.Add($"开放端口提示: {hint}");
            if (hint.Contains("Windows")) { scores["Windows"] = scores.GetValueOrDefault("Windows") + 35; scores["Windows Server"] = scores.GetValueOrDefault("Windows Server") + 30; }
            if (hint.Contains("Linux")) { scores["Linux"] = scores.GetValueOrDefault("Linux") + 35; scores["Android"] = scores.GetValueOrDefault("Android") + 15; }
            if (hint.Contains("macOS")) { scores["macOS"] = scores.GetValueOrDefault("macOS") + 35; }
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
        var ttlSupportsBest = possibleInitialTtls.Any(value => TtlMap[value].Contains(best.Key));
        var conflictingHint = portHints.Any(hint =>
            !possibleInitialTtls.Any(value => TtlMap[value].Any(os => hint.Contains(os, StringComparison.Ordinal))));
        if (portHints.Count > 0 && (!ttlSupportsBest || conflictingHint))
        {
            confidence = Math.Min(confidence, 45);
            reasons.Add("低置信度：TTL 家族与部分端口平台提示不一致，不提高确定性");
        }
        else if (portHints.Count > 0 && confidence > 50)
            reasons.Add("TTL 家族与开放端口平台线索一致；置信度已提高，但仍不是主动 TCP/IP OS 指纹");
        if (possibleInitialTtls.Length > 1)
        {
            reasons.Add("TTL 跳数不确定，评分仅表示启发式证据强弱，不是统计概率或 OS 确认");
            confidence = Math.Min(confidence, 60);
        }
        return (best.Key, confidence, reasons.ToArray());
    }

    internal static bool IsLocalTarget(string target)
    {
        if (!IPAddress.TryParse(target, out var address)) return false;
        if (IPAddress.IsLoopback(address)) return true;
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                .SelectMany(nic => nic.GetIPProperties().UnicastAddresses)
                .Any(item => item.Address.Equals(address));
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }
}
