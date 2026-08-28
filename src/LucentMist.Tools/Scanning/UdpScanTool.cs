using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

public class UdpScanTool : INetworkTargetTool
{
    private readonly ILogger<UdpScanTool> _logger;

    public string Name => "udp_scan";
    public string Description => "UDP 端口扫描，探测常见 UDP 服务端口（DNS/SNMP/NTP 等），支持端口范围如 1-1000 或 53,123,161";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标 IP", Required = true },
        new() { Name = "ports", Type = "string", Description = "端口范围，如 1-1000 或 53,123,161", Required = false, Default = "53,123,161,500,514,1900" },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "3000" },
        new() { Name = "concurrency", Type = "int", Description = "并发数", Required = false, Default = "20" }
    ];

    public UdpScanTool(ILogger<UdpScanTool> logger) => _logger = logger;

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var portsStr = args.GetOrDefault("ports", "53,123,161,500,514,1900");
        var timeout = Math.Clamp(args.GetInt("timeout_ms", 3000), 100, 60_000);
        var concurrency = Math.Clamp(args.GetInt("concurrency", 20), 1, 500);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标 IP", sw.Elapsed);
        var resolvedTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
        if (resolvedTarget == null)
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
        target = resolvedTarget;

        try
        {
            var ports = PortHelper.ParsePorts(portsStr);

            _logger.LogInformation("UdpScan: Target={Target}, Ports={Count}", target, ports.Count);

            var openPorts = new List<int>();
            using var semaphore = new SemaphoreSlim(concurrency);

            var tasks = ports.Select(async port =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (await ProbeUdpAsync(target, port, timeout, cancellationToken))
                    {
                        lock (openPorts) openPorts.Add(port);
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
                services = openPorts.ToDictionary(p => p, p => PortHelper.GetUdpServiceName(p) ?? "unknown"),
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation("UdpScan done: Open={Open}/{Total}", openPorts.Count, ports.Count);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UdpScan failed");
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    private static async Task<bool> ProbeUdpAsync(string ip, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = timeoutMs;
            client.Client.SendTimeout = timeoutMs;
            client.Connect(ip, port);

            byte[] probe = port switch
            {
                53 => new byte[] { 0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 4, 0x62, 0x69, 0x6E, 0x64, 0, 0, 0x10, 0, 3 },
                123 => new byte[48], // NTP
                161 => new byte[] { 0x30, 0x26, 0x02, 0x01, 0, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x19, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0, 0x05, 0x00 },
                _ => new byte[] { 0 }
            };

            await client.SendAsync(probe, probe.Length);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            try
            {
                var response = await client.ReceiveAsync(cts.Token);
                return response.Buffer.Length > 0;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException) { return false; }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }
}
