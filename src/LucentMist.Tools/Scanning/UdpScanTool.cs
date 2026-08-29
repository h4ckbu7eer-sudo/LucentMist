using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

public class UdpScanTool : INetworkTargetTool
{
    private const string DefaultPorts = "53,123,161,1900";
    private readonly ILogger<UdpScanTool> _logger;

    public string Name => "udp_scan";
    public string Description => "UDP 端口扫描，探测常见 UDP 服务端口（DNS/SNMP/NTP 等），支持端口范围如 1-1000 或 53,123,161";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标 IP", Required = true },
        new() { Name = "ports", Type = "string", Description = "端口范围，如 1-1000 或 53,123,161", Required = false, Default = DefaultPorts },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "3000" },
        new() { Name = "concurrency", Type = "int", Description = "并发数", Required = false, Default = "20" }
    ];

    public UdpScanTool(ILogger<UdpScanTool> logger) => _logger = logger;

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var portsStr = args.GetOrDefault("ports", DefaultPorts);
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
            if (!PortHelper.TryParsePorts(portsStr, out var ports))
                return ToolResult.Fail("端口必须是 1-65535 的数字、逗号列表或正向范围", sw.Elapsed);

            _logger.LogInformation("UdpScan: Target={Target}, Ports={Count}", target, ports.Count);

            var probeResults = new ConcurrentBag<UdpPortResult>();
            await Parallel.ForEachAsync(
                ports,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = concurrency,
                    CancellationToken = cancellationToken,
                },
                async (port, ct) =>
                {
                    probeResults.Add(await ProbeUdpAsync(target, port, timeout, ct));
                });
            var orderedResults = probeResults.OrderBy(result => result.Port).ToArray();
            var openPorts = orderedResults
                .Where(result => result.State == "open")
                .Select(result => result.Port)
                .ToArray();

            var result = new
            {
                target,
                totalScanned = ports.Count,
                openPorts,
                services = openPorts.ToDictionary(p => p, p => PortHelper.GetUdpServiceName(p) ?? "unknown"),
                ports = orderedResults.Select(item => new
                {
                    port = item.Port,
                    service = item.Service,
                    state = item.State,
                    detail = item.Detail
                }),
                openFilteredPorts = orderedResults.Where(item => item.State == "open|filtered").Select(item => item.Port),
                closedPorts = orderedResults.Where(item => item.State == "closed").Select(item => item.Port),
                unprobeablePorts = orderedResults.Where(item => item.State == "unprobeable").Select(item => item.Port),
                interpretation = "UDP 无响应标记为 open|filtered；unprobeable 表示没有可靠协议探测；closed 基于不可达或连接重置推断，防火墙重置可能造成误判",
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation(
                "UdpScan done: Open={Open}, OpenFiltered={OpenFiltered}, Closed={Closed}, Unprobeable={Unprobeable}, Total={Total}",
                openPorts.Length,
                orderedResults.Count(item => item.State == "open|filtered"),
                orderedResults.Count(item => item.State == "closed"),
                orderedResults.Count(item => item.State == "unprobeable"),
                ports.Count);
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

    private static async Task<UdpPortResult> ProbeUdpAsync(
        string ip,
        int port,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var service = PortHelper.GetUdpServiceName(port) ?? "unknown";
        if (!TryCreateProbe(port, out var probe, out var unsupportedReason))
            return new UdpPortResult(port, service, "unprobeable", unsupportedReason!);

        return await ProbeUdpEndpointAsync(
            ip,
            port,
            service,
            probe,
            timeoutMs,
            cancellationToken);
    }

    internal static async Task<UdpPortResult> ProbeUdpEndpointAsync(
        string ip,
        int port,
        string service,
        byte[] probe,
        int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new UdpClient();
            client.Client.ReceiveTimeout = timeoutMs;
            client.Client.SendTimeout = timeoutMs;
            client.Connect(ip, port);

            await client.SendAsync(probe, cancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            try
            {
                var response = await client.ReceiveAsync(cts.Token);
                return response.Buffer.Length > 0
                    ? new UdpPortResult(port, service, "open", $"收到 {response.Buffer.Length} 字节 UDP 响应")
                    : new UdpPortResult(port, service, "open|filtered", "收到空 UDP 数据报，无法确认服务");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                return new UdpPortResult(port, service, "open|filtered", "探测超时：端口可能开放但静默，也可能被过滤");
            }
            catch (SocketException ex) when (IsIcmpUnreachable(ex.SocketErrorCode))
            {
                return new UdpPortResult(
                    port,
                    service,
                    "closed",
                    ClosedInferenceDetail(ex.SocketErrorCode));
            }
            catch (SocketException ex)
            {
                return new UdpPortResult(port, service, "open|filtered", $"未获得确定响应: {ex.SocketErrorCode}");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException ex) when (IsIcmpUnreachable(ex.SocketErrorCode))
        {
            return new UdpPortResult(
                port,
                service,
                "closed",
                ClosedInferenceDetail(ex.SocketErrorCode));
        }
        catch (Exception ex)
        {
            return new UdpPortResult(port, service, "open|filtered", $"探测未获得确定结果: {ex.Message}");
        }
    }

    internal static bool TryCreateProbe(
        int port,
        out byte[] probe,
        out string? unsupportedReason)
    {
        unsupportedReason = null;
        probe = port switch
        {
            53 => new byte[] { 0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 4, 0x62, 0x69, 0x6E, 0x64, 0, 0, 0x10, 0, 3 },
            123 => CreateNtpClientProbe(),
            161 => new byte[] { 0x30, 0x26, 0x02, 0x01, 0, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA0, 0x19, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0, 0x05, 0x00 },
            1900 => Encoding.ASCII.GetBytes(
                "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 1\r\n" +
                "ST: ssdp:all\r\n\r\n"),
            _ => Array.Empty<byte>()
        };

        if (probe.Length > 0)
            return true;

        unsupportedReason = port switch
        {
            500 => "IKE/ISAKMP 需要会话相关协商载荷，当前无可靠的无状态探测",
            514 => "syslog UDP 通常不响应请求，无法通过无状态探测确认",
            _ => "该 UDP 服务没有已实现的可靠协议探测"
        };
        return false;
    }

    private static byte[] CreateNtpClientProbe()
    {
        var probe = new byte[48];
        probe[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
        return probe;
    }

    private static bool IsIcmpUnreachable(SocketError error) => error is
        SocketError.ConnectionReset or
        SocketError.ConnectionRefused or
        SocketError.HostUnreachable or
        SocketError.NetworkUnreachable;

    internal static string ClosedInferenceDetail(SocketError error) =>
        error == SocketError.ConnectionReset
            ? "收到连接重置；可能是目标拒绝或防火墙重置，closed 为推断状态"
            : $"收到不可达/拒绝错误: {error}；closed 为推断状态";

    internal sealed record UdpPortResult(
        int Port,
        string Service,
        string State,
        string Detail);
}
