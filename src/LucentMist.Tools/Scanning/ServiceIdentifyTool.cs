using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 服务识别工具 — Banner 抓取 + 服务识别 + 本机进程信息
/// </summary>
public class ServiceIdentifyTool : ITool
{
    private readonly ILogger<ServiceIdentifyTool> _logger;
    private static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };

    public string Name => "service_identify";
    public string Description => "识别目标 IP 指定端口上运行的服务，通过 Banner 抓取判断服务类型，本机可显示进程信息";

    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标 IP 地址", Required = true },
        new() { Name = "port", Type = "int", Description = "端口号", Required = true },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "5000" }
    ];

    // 常见端口 → 服务名映射
    // 懒加载：本机端口→PID 映射缓存
    private static Dictionary<int, int>? _portPidCache;
    private static DateTime _portPidCacheTime = DateTime.MinValue;
    private static readonly object PortPidLock = new();

    public ServiceIdentifyTool(ILogger<ServiceIdentifyTool> logger)
    {
        _logger = logger;
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var port = args.GetInt("port");
        var timeout = args.GetInt("timeout_ms", 5000);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标 IP", sw.Elapsed);
        if (port is < 1 or > 65535)
            return ToolResult.Fail("端口号必须在 1-65535 之间", sw.Elapsed);
        var resolvedTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
        if (resolvedTarget == null)
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);
        target = resolvedTarget;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("ServiceIdentify: {Target}:{Port}", target, port);

            var serviceName = PortHelper.GetServiceKey(port) ?? "unknown";
            string? banner = null;

            // 尝试抓取 Banner（HTTP / SSH / 通用）
            banner = await GrabBannerAsync(target, port, timeout, cancellationToken);

            // HTTP 回退：如果是 80/443/8080，尝试 HTTP GET
            if (banner == null && port is 80 or 443 or 8080 or 8443)
            {
                banner = await GrabHttpBannerAsync(target, port, timeout, cancellationToken);
            }

            // 本机 → 获取进程信息
            object? procInfo = null;
            var processInfoAvailable = false;
            string? processInfoError = null;
            if (IsLocalTarget(target))
            {
                try
                {
                    procInfo = GetProcessInfo(port);
                    processInfoAvailable = procInfo != null;
                    if (procInfo == null)
                    {
                        processInfoError = OperatingSystem.IsWindows()
                            ? "未找到端口对应进程"
                            : "当前平台无法读取进程信息，可能需要 root 权限";
                    }
                }
                catch (Exception ex)
                {
                    processInfoError = ex.Message;
                }
            }

            var result = new
            {
                target,
                port,
                serviceName,
                banner,
                identified = banner != null,
                process = procInfo,
                processInfoAvailable,
                processInfoError
            };

            _logger.LogInformation("ServiceIdentify 完成: {Target}:{Port} → {Service}",
                target, port, serviceName);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ServiceIdentify 失败");
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    // ========================================
    // 本机进程信息
    // ========================================

    private static bool IsLocalTarget(string target)
    {
        if (target == "127.0.0.1" || target == "localhost" || target == "::1")
            return true;

        // 检查是否匹配本机任一网卡 IP
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var addr in nic.GetIPProperties().UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork &&
                    addr.Address.ToString() == target)
                    return true;
            }
        }
        return false;
    }

    private Dictionary<int, int> GetPortPidMap()
    {
        lock (PortPidLock)
        {
            // 缓存 3 秒
            if (_portPidCache != null && (DateTime.UtcNow - _portPidCacheTime).TotalSeconds < 3)
                return _portPidCache;

            var map = new Dictionary<int, int>();
            try
            {
                var psi = OperatingSystem.IsWindows()
                    ? new ProcessStartInfo("netstat", "-ano")
                    : new ProcessStartInfo("ss", "-tulnp");
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;

                using var proc = Process.Start(psi);
                if (proc == null) return map;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                map = OperatingSystem.IsWindows()
                    ? ParseWindowsNetstat(output)
                    : ParseLinuxSs(output);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read port to PID map");
            }

            _portPidCache = map;
            _portPidCacheTime = DateTime.UtcNow;
            return map;
        }
    }

    internal static Dictionary<int, int> ParseWindowsNetstat(string output)
    {
        var map = new Dictionary<int, int>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("TCP")) continue;

            var parts = Regex.Split(trimmed, @"\s+");
            if (parts.Length < 5) continue;

            var local = parts[1];
            var pidStr = parts[^1];
            var colon = local.LastIndexOf(':');
            if (colon < 0) continue;

            if (int.TryParse(local[(colon + 1)..], out var port) &&
                int.TryParse(pidStr, out var pid))
            {
                if (!map.ContainsKey(port))
                    map[port] = pid;
            }
        }
        return map;
    }

    internal static Dictionary<int, int> ParseLinuxSs(string output)
    {
        var map = new Dictionary<int, int>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("tcp")) continue;

            var parts = Regex.Split(trimmed, @"\s+");
            if (parts.Length < 4) continue;

            var local = parts[2];
            var processPart = parts[^1];
            var portMatch = Regex.Match(local, @":(\d+)$");
            var pidMatch = Regex.Match(processPart, @"pid=(\d+)");
            if (!portMatch.Success || !pidMatch.Success) continue;

            if (int.TryParse(portMatch.Groups[1].Value, out var port) &&
                int.TryParse(pidMatch.Groups[1].Value, out var pid) &&
                !map.ContainsKey(port))
            {
                map[port] = pid;
            }
        }
        return map;
    }

    private object? GetProcessInfo(int port)
    {
        try
        {
            var portPid = GetPortPidMap();
            if (!portPid.TryGetValue(port, out var pid))
                return null;

            Process proc;
            try { proc = Process.GetProcessById(pid); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get process {Pid}", pid);
                return null;
            }
            using var processHandle = proc;

            var procName = processHandle.ProcessName;
            string? procPath = null;
            try { procPath = processHandle.MainModule?.FileName; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read process path for {Process}", procName);
            }

            // 查找关联的 Windows 服务
            string? serviceName = null;
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    foreach (var svc in ServiceController.GetServices())
                    {
                        if (svc.ServiceName.Equals(procName, StringComparison.OrdinalIgnoreCase) ||
                            (procPath != null && procPath.Contains(svc.ServiceName, StringComparison.OrdinalIgnoreCase)))
                        {
                            serviceName = svc.ServiceName;
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to enumerate Windows services for {Process}", procName);
                }
            }

            // 如果没有直接匹配，检查常见端口→服务映射
            if (serviceName == null)
            {
                serviceName = port switch
                {
                    135 => "RpcSs/RpcEptMapper",
                    139 or 445 => "LanmanServer",
                    3389 => "TermService",
                    _ => null
                };
            }

            return new
            {
                pid,
                processName = procName,
                path = procPath,
                service = serviceName
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to inspect process info for port {Port}", port);
            return null;
        }
    }

    private async Task<string?> GrabBannerAsync(string ip, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            using var client = new TcpClient();
            await client.ConnectAsync(ip, port, cts.Token);

            using var stream = client.GetStream();
            var buffer = new byte[1024];
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(), cts.Token);
            return bytesRead > 0
                ? Encoding.UTF8.GetString(buffer, 0, bytesRead).Replace("\r\n", " ").Replace('\0', ' ').Trim()
                : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> GrabHttpBannerAsync(string ip, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var scheme = port is 443 or 8443 ? "https" : "http";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);
            using var response = await Http.GetAsync($"{scheme}://{ip}:{port}/", cts.Token);
            var serverHeader = response.Headers.Server?.ToString();
            return $"HTTP {(int)response.StatusCode} {response.StatusCode}, Server: {serverHeader ?? "unknown"}";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}
