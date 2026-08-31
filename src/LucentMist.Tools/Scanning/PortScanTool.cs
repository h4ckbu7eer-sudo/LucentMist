using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;
using LucentMist.Tools.Discovery;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 端口扫描工具 — TCP SYN/Connect 端口扫描
/// </summary>
public class PortScanTool : INetworkTargetTool
{
    private readonly ILogger<PortScanTool> _logger;

    public string Name => "port_scan";
    public string Description => "扫描目标 IP 的开放 TCP 端口";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标 IP 地址", Required = true },
        new() { Name = "ports", Type = "string", Description = "端口范围，如 1-1000 或 80,443,8080", Required = false, Default = "1-1000" },
        new() { Name = "timeout_ms", Type = "int", Description = "每个端口超时(毫秒)", Required = false, Default = "2000" },
        new() { Name = "concurrency", Type = "int", Description = "并发数", Required = false, Default = "100" }
    ];

    public PortScanTool(ILogger<PortScanTool> logger)
    {
        _logger = logger;
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var portsStr = args.GetOrDefault("ports", "1-1000");
        var timeout = Math.Clamp(args.GetInt("timeout_ms", 2000), 100, 60_000);
        var concurrency = Math.Clamp(args.GetInt("concurrency", 100), 1, 500);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标 IP", sw.Elapsed);
        var resolvedTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
        if (resolvedTarget == null)
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
        target = resolvedTarget;

        try
        {
            if (!PortHelper.TryParsePorts(portsStr, out var ports))
                return ToolResult.Fail("端口必须是 1-65535 的数字、逗号列表或正向范围", sw.Elapsed);
            _logger.LogInformation("PortScan 开始: Target={Target}, Ports={Count}", target, ports.Count);
            var deviceTask = DeviceDiscovery.EnrichAsync(target, cancellationToken);

            var openPorts = new List<int>();
            await Parallel.ForEachAsync(
                ports,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = concurrency,
                    CancellationToken = cancellationToken,
                },
                async (port, ct) =>
                {
                    if (await ScanPortAsync(target, port, timeout, ct))
                    {
                        lock (openPorts) { openPorts.Add(port); }
                    }
                });
            openPorts.Sort();
            var device = await deviceTask;

            var result = new
            {
                target,
                totalScanned = ports.Count,
                scannedPortRange = portsStr,
                scopeNote = "仅报告本次 TCP 受检端口；范围外端口及 WAN 可达性均未知。",
                openPorts,
                device,
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation("PortScan 完成: Open={Open}/{Total}", openPorts.Count, ports.Count);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PortScan 失败");
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    /// <summary>
    /// 扫描单个端口
    /// </summary>
    private async Task<bool> ScanPortAsync(string ip, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port, cts.Token);
            if (client.Connected)
                client.Client.LingerState = new LingerOption(true, 0);
            return client.Connected;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) { return false; }
        catch { return false; }
    }
}
