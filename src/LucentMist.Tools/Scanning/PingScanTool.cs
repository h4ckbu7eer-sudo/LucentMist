using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 存活探测工具 — ICMP Ping / TCP SYN 探测局域网设备
/// </summary>
public class PingScanTool : ITool
{
    private readonly ILogger<PingScanTool> _logger;
    private int _icmpBlocked;

    public string Name => "ping_scan";
    public string Description => "探测网络中存活设备，支持 CIDR 子网（如 192.168.1.0/24）";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标子网或 IP", Required = true },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "3000" },
        new() { Name = "concurrency", Type = "int", Description = "并发数", Required = false, Default = "50" }
    ];

    public PingScanTool(ILogger<PingScanTool> logger)
    {
        _logger = logger;
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var timeout = Math.Clamp(args.GetInt("timeout_ms", 3000), 100, 60_000);
        var concurrency = Math.Clamp(args.GetInt("concurrency", 50), 1, 500);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标子网", sw.Elapsed);

        try
        {
            _logger.LogInformation("PingScan 开始: Target={Target}, Timeout={Timeout}ms", target, timeout);

            var ips = ParseTarget(target);
            var alive = new List<string>();

            using var semaphore = new SemaphoreSlim(concurrency);
            var tasks = ips.Select(async ip =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (await PingHostAsync(ip, timeout, cancellationToken))
                    {
                        lock (alive) { alive.Add(ip); }
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            var result = new
            {
                target,
                total = ips.Count,
                alive = alive.Count,
                devices = alive,
                hint = alive.Count == 0
                    ? $"目标 {target} 无设备响应。请确认：1) 子网是否与当前网卡匹配 2) 防火墙是否阻止 ICMP"
                    : null,
                icmpFallback = Volatile.Read(ref _icmpBlocked) != 0
                    ? "ICMP 不可用，已使用 TCP 端口探测（80/443/22/445）"
                    : null,
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
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeoutMs).WaitAsync(cancellationToken);
                if (reply.Status == IPStatus.Success)
                    return true;
                if (reply.Status != IPStatus.TimedOut)
                    return false;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (PingException ex) when (IsPermissionError(ex))
            {
                Volatile.Write(ref _icmpBlocked, 1);
                _logger.LogWarning("ICMP Ping 无权限，后续回退 TCP 探测: {Target}", ip);
            }
            catch (UnauthorizedAccessException)
            {
                Volatile.Write(ref _icmpBlocked, 1);
                _logger.LogWarning("ICMP Ping 无权限，后续回退 TCP 探测: {Target}", ip);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Ping 失败: {Target}", ip);
            }
        }

        return await TcpProbeAsync(ip, timeoutMs, cancellationToken);
    }

    private static async Task<bool> TcpProbeAsync(string ip, int timeoutMs, CancellationToken cancellationToken)
    {
        foreach (var port in new[] { 80, 443, 22, 445 })
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(Math.Min(timeoutMs, 1500));
                using var client = new TcpClient();
                await client.ConnectAsync(ip, port, cts.Token);
                return true;
            }
            catch
            {
                // 尝试下一个端口
            }
        }
        return false;
    }

    private static bool IsPermissionError(PingException ex)
    {
        if (ex.InnerException is UnauthorizedAccessException) return true;
        if (ex.InnerException is SocketException socket && socket.SocketErrorCode is SocketError.AccessDenied)
            return true;
        return ex.Message.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
               ex.Message.Contains("access", StringComparison.OrdinalIgnoreCase);
    }
}
