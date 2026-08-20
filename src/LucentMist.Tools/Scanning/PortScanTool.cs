using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Tools.Common;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 端口扫描工具 — TCP SYN/Connect 端口扫描
/// </summary>
public class PortScanTool : ITool
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

        try
        {
            var ports = PortHelper.ParsePorts(portsStr);
            _logger.LogInformation("PortScan 开始: Target={Target}, Ports={Count}", target, ports.Count);

            var openPorts = new List<int>();
            using var semaphore = new SemaphoreSlim(concurrency);

            var tasks = ports.Select(async port =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (await ScanPortAsync(target, port, timeout, cancellationToken))
                    {
                        lock (openPorts) { openPorts.Add(port); }
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            openPorts.Sort();

            var result = new
            {
                target,
                totalScanned = ports.Count,
                openPorts,
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
