using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 存活探测工具 — ICMP Ping / TCP SYN 探测局域网设备
/// </summary>
public class PingScanTool : ITool
{
    private readonly ILogger<PingScanTool> _logger;

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

    public async Task<ToolResult> ExecuteAsync(ToolArguments args)
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
                await semaphore.WaitAsync();
                try
                {
                    if (await PingHostAsync(ip, timeout))
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
                devices = alive
            };

            _logger.LogInformation("PingScan 完成: Alive={Alive}/{Total}", alive.Count, ips.Count);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
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
    private List<string> ParseTarget(string target)
    {
        var ips = new List<string>();

        // 单个 IP
        if (IPAddress.TryParse(target, out _) && !target.Contains('/'))
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
            if (prefix is < 8 or > 30)
                throw new ArgumentException($"CIDR 前缀 /{prefix} 超出允许范围 /8 ~ /30");

            var hostCount = (int)((1L << (32 - prefix)) - 2);
            if (hostCount > 65534)
                throw new ArgumentException($"CIDR /{prefix} 范围过大（{hostCount} 主机），最大支持 65534 个主机");

            var mask = 0xFFFFFFFFu << (32 - prefix);
            var network = BitConverter.ToUInt32(baseBytes.Reverse().ToArray(), 0) & mask;
            var broadcast = network | ~mask;

            for (var addr = network + 1; addr < broadcast; addr++)
            {
                var bytes = BitConverter.GetBytes(addr);
                Array.Reverse(bytes);
                ips.Add(new IPAddress(bytes).ToString());
            }
        }

        return ips;
    }

    /// <summary>
    /// Ping 单个主机
    /// </summary>
    private async Task<bool> PingHostAsync(string ip, int timeoutMs)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeoutMs);
            return reply.Status == IPStatus.Success;
        }
        catch
        {
            return false;
        }
    }
}
