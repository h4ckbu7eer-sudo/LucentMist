using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using LucentMist.Core.Networking;
using LucentMist.Tools.Discovery;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 存活探测工具 — ICMP Ping / TCP SYN 探测局域网设备
/// </summary>
public class PingScanTool : INetworkTargetTool
{
    private readonly ILogger<PingScanTool> _logger;
    private readonly Func<string, int, CancellationToken, Task<IPStatus>> _icmpProbeAsync;
    private readonly Func<string, int, CancellationToken, Task<bool>> _tcpProbeAsync;
    private readonly Func<IReadOnlyCollection<string>, CancellationToken, Task<IReadOnlyDictionary<string, string>>> _neighborLookupAsync;
    private readonly Func<string, CancellationToken, Task<string?>> _mdnsLookupAsync;
    private readonly OuiDatabase _ouiDatabase;
    private readonly Func<string, CancellationToken, Task<MdnsProbe.Identity>>? _identityProbe;
    private const int IcmpNoResponse = 1;
    private const int IcmpRejected = 2;
    private const int IcmpUnavailable = 4;
    private int _icmpBlocked;
    private int _icmpFallbackReasons;

    public string Name => "ping_scan";
    public string Description => "探测网络中存活设备，支持 CIDR 子网（如 192.168.1.0/24）";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标子网或 IP", Required = true },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "3000" },
        new() { Name = "concurrency", Type = "int", Description = "并发数", Required = false, Default = "50" }
    ];

    public PingScanTool(ILogger<PingScanTool> logger)
        : this(logger, SendIcmpAsync, TcpProbeAsync, NeighborTable.ReadAsync, MdnsProbe.ResolveNameAsync, new OuiDatabase())
    {
        _identityProbe = MdnsProbe.ProbeAsync;
    }

    internal PingScanTool(
        ILogger<PingScanTool> logger,
        Func<string, int, CancellationToken, Task<IPStatus>> icmpProbeAsync,
        Func<string, int, CancellationToken, Task<bool>> tcpProbeAsync)
        : this(logger, icmpProbeAsync, tcpProbeAsync,
            (_, _) => Task.FromResult<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>()),
            (_, _) => Task.FromResult<string?>(null), new OuiDatabase())
    {
    }

    internal PingScanTool(
        ILogger<PingScanTool> logger,
        Func<string, int, CancellationToken, Task<IPStatus>> icmpProbeAsync,
        Func<string, int, CancellationToken, Task<bool>> tcpProbeAsync,
        Func<IReadOnlyCollection<string>, CancellationToken, Task<IReadOnlyDictionary<string, string>>> neighborLookupAsync,
        Func<string, CancellationToken, Task<string?>> mdnsLookupAsync,
        OuiDatabase ouiDatabase)
    {
        _logger = logger;
        _icmpProbeAsync = icmpProbeAsync;
        _tcpProbeAsync = tcpProbeAsync;
        _neighborLookupAsync = neighborLookupAsync;
        _mdnsLookupAsync = mdnsLookupAsync;
        _ouiDatabase = ouiDatabase;
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var requestedTarget = target;
        var timeout = Math.Clamp(args.GetInt("timeout_ms", 3000), 100, 60_000);
        var concurrency = Math.Clamp(args.GetInt("concurrency", 50), 1, 500);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标子网", sw.Elapsed);
        if (!target.Contains('/') && !IPAddress.TryParse(target, out _))
        {
            var resolvedTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
            if (resolvedTarget == null)
                return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
            target = resolvedTarget;
        }
        else if (!await TargetGuard.IsAllowedAsync(target, cancellationToken))
        {
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
        }

        try
        {
            Volatile.Write(ref _icmpFallbackReasons, 0);
            _logger.LogInformation("PingScan 开始: Target={Target}, Timeout={Timeout}ms", target, timeout);

            var ips = ParseTarget(target);
            var alive = new List<string>();
            await Parallel.ForEachAsync(
                ips,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = concurrency,
                    CancellationToken = cancellationToken,
                },
                async (ip, ct) =>
                {
                    if (await PingHostAsync(ip, timeout, ct))
                    {
                        lock (alive) { alive.Add(ip); }
                    }
                });
            alive.Sort(StringComparer.Ordinal);
            var neighborTable = await _neighborLookupAsync(alive, cancellationToken);
            var deviceDetails = new DeviceDetail[alive.Count];
            await Parallel.ForEachAsync(
                Enumerable.Range(0, alive.Count),
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Min(8, Math.Max(1, alive.Count)),
                    CancellationToken = cancellationToken,
                },
                async (index, ct) =>
                {
                    var ip = alive[index];
                    neighborTable.TryGetValue(ip, out var mac);
                    var identity = IsPrivateAddress(ip) && _identityProbe != null ? await _identityProbe(ip, ct) : null;
                    var name = identity?.Name ?? (IsPrivateAddress(ip) && _identityProbe == null ? await _mdnsLookupAsync(ip, ct) : null);
                    deviceDetails[index] = new DeviceDetail(
                        ip,
                        mac,
                        _ouiDatabase.Lookup(mac) ?? "未知",
                        name ?? "未知（未获得有效名称响应）",
                        identity?.Model ?? "未知（需服务指纹或管理接口确认）");
                });

            var result = new
            {
                target = requestedTarget,
                total = ips.Count,
                alive = alive.Count,
                devices = alive,
                deviceDetails,
                hint = alive.Count == 0
                    ? $"目标 {requestedTarget} 无设备响应。请确认：1) 子网是否与当前网卡匹配 2) 防火墙是否阻止 ICMP"
                    : null,
                icmpFallback = DescribeIcmpFallback(
                    Volatile.Read(ref _icmpFallbackReasons)),
            };

            _logger.LogInformation("PingScan 完成: Alive={Alive}/{Total}", alive.Count, ips.Count);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PingScan 失败");
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    private static bool IsPrivateAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
               (bytes[0] == 10 || bytes[0] == 127 ||
                bytes[0] == 192 && bytes[1] == 168 ||
                bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                bytes[0] == 169 && bytes[1] == 254);
    }

    internal sealed record DeviceDetail(
        [property: JsonPropertyName("ip")] string Ip,
        [property: JsonPropertyName("mac")] string? Mac,
        [property: JsonPropertyName("vendor")] string Vendor,
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("model")] string Model);

    /// <summary>
    /// 解析 CIDR 或 IP 范围为目标 IP 列表
    /// </summary>
    internal List<string> ParseTarget(string target)
    {
        var ips = new List<string>();

        // 单个 IP
        if (IPAddress.TryParse(target, out _) && !target.Contains('/'))
        {
            ips.Add(target);
            return ips;
        }

        // 单个主机名/域名：交给 Ping.SendPingAsync 解析
        if (!target.Contains('/'))
        {
            ips.Add(target);
            return ips;
        }

        // CIDR 子网 (边界校验: 仅 IPv4, /8~/30, 最多 65534 主机)
        if (target.Contains('/'))
        {
            var parts = target.Split('/');
            if (!IPAddress.TryParse(parts[0], out var baseIp))
                throw new ArgumentException($"非法目标: '{target}' — 不是合法的 IP 或 CIDR");
            if (!int.TryParse(parts[1], out var prefix))
                throw new ArgumentException($"非法 CIDR 前缀: '{target}'");

            var baseBytes = baseIp.GetAddressBytes();
            if (baseBytes.Length != 4)
                throw new ArgumentException($"仅支持 IPv4 地址: '{target}'");
            if (prefix is < 8 or > 32)
                throw new ArgumentException($"CIDR 前缀 /{prefix} 超出允许范围 /8 ~ /32");

            if (prefix == 32)
            {
                ips.Add(baseIp.ToString());
                return ips;
            }

            var baseValue = BitConverter.ToUInt32(Enumerable.Reverse(baseBytes).ToArray(), 0);
            if (prefix == 31)
            {
                var mask31 = 0xFFFFFFFFu << 1;
                var network31 = baseValue & mask31;
                ips.Add(ToIpString(network31));
                ips.Add(ToIpString(network31 | 1));
                return ips;
            }

            var hostCount = (int)((1L << (32 - prefix)) - 2);
            if (hostCount > 65534)
                throw new ArgumentException($"CIDR /{prefix} 范围过大（{hostCount} 主机），最大支持 65534 个主机");

            var mask = 0xFFFFFFFFu << (32 - prefix);
            var network = baseValue & mask;
            var broadcast = network | ~mask;

            for (var addr = network + 1; addr < broadcast; addr++)
                ips.Add(ToIpString(addr));
        }

        return ips;
    }

    private static string ToIpString(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        Array.Reverse(bytes);
        return new IPAddress(bytes).ToString();
    }

    /// <summary>
    /// Ping 单个主机
    /// </summary>
    private async Task<bool> PingHostAsync(string ip, int timeoutMs, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _icmpBlocked) == 0)
        {
            try
            {
                var status = await _icmpProbeAsync(ip, timeoutMs, cancellationToken);
                if (status == IPStatus.Success)
                    return true;
                if (!ShouldFallbackToTcp(status))
                    return false;
                RecordFallbackReason(status == IPStatus.TimedOut
                    ? IcmpNoResponse
                    : IcmpRejected);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (PingException ex) when (IsPermissionError(ex))
            {
                Volatile.Write(ref _icmpBlocked, 1);
                RecordFallbackReason(IcmpUnavailable);
                _logger.LogDebug("ICMP Ping 无权限，后续回退 TCP 探测: {Target}", ip);
            }
            catch (UnauthorizedAccessException)
            {
                Volatile.Write(ref _icmpBlocked, 1);
                RecordFallbackReason(IcmpUnavailable);
                _logger.LogDebug("ICMP Ping 无权限，后续回退 TCP 探测: {Target}", ip);
            }
            catch (Exception ex)
            {
                RecordFallbackReason(IcmpUnavailable);
                _logger.LogDebug(ex, "Ping 失败: {Target}", ip);
            }
        }
        else
        {
            RecordFallbackReason(IcmpUnavailable);
        }

        return await _tcpProbeAsync(ip, timeoutMs, cancellationToken);
    }

    private void RecordFallbackReason(int reason) =>
        Interlocked.Or(ref _icmpFallbackReasons, reason);

    internal static string? DescribeIcmpFallback(int reasons)
    {
        if (reasons == 0) return null;

        var descriptions = new List<string>();
        if ((reasons & IcmpNoResponse) != 0) descriptions.Add("ICMP 无响应");
        if ((reasons & IcmpRejected) != 0) descriptions.Add("ICMP 被拒绝");
        if ((reasons & IcmpUnavailable) != 0) descriptions.Add("ICMP 不可用");
        return $"{string.Join("；", descriptions)}，已使用 TCP 端口探测（80/443/22/445）";
    }

    private static async Task<IPStatus> SendIcmpAsync(
        string ip,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        var reply = await ping.SendPingAsync(ip, timeoutMs).WaitAsync(cancellationToken);
        return reply.Status;
    }

    private static async Task<bool> TcpProbeAsync(string ip, int timeoutMs, CancellationToken cancellationToken)
    {
        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCts.CancelAfter(Math.Min(timeoutMs, 1500));
        var tasks = new[] { 80, 443, 22, 445 }
            .Select(port => ProbeTcpPortAsync(ip, port, probeCts.Token))
            .ToList();

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks);
            tasks.Remove(completed);
            if (await completed)
            {
                probeCts.Cancel();
                return true;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return false;
    }

    private static async Task<bool> ProbeTcpPortAsync(
        string ip,
        int port,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port, cancellationToken);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsPermissionError(PingException ex)
    {
        if (ex.InnerException is UnauthorizedAccessException) return true;
        if (ex.InnerException is SocketException socket && socket.SocketErrorCode is SocketError.AccessDenied)
            return true;
        return ex.Message.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
               ex.Message.Contains("access", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool ShouldFallbackToTcp(IPStatus status) => status is
        IPStatus.TimedOut or
        IPStatus.DestinationUnreachable or
        IPStatus.DestinationHostUnreachable or
        IPStatus.DestinationProtocolUnreachable or
        IPStatus.DestinationPortUnreachable or
        IPStatus.DestinationNetworkUnreachable;
}
