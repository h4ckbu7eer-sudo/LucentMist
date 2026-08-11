using System.Text.Json;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LucentMist.Scanning;

/// <summary>
/// 后台扫描 worker — 从 Channel 消费任务，调用真实扫描工具，状态落 SQLite 并推送进度。
/// 并发上限 1，防止 /24 级大范围扫描打爆资源。
/// </summary>
public sealed class ScanWorker : BackgroundService
{
    private readonly ScanCoordinator _coordinator;
    private readonly ScanStore _store;
    private readonly IScanProgressPublisher _progress;
    private readonly ILogger<ScanWorker> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ILoggerFactory _loggerFactory;
    private readonly PingScanTool _pingTool;
    private readonly PortScanTool _portTool;
    private readonly UdpScanTool _udpTool;

    public ScanWorker(
        ScanCoordinator coordinator,
        ScanStore store,
        IScanProgressPublisher progress,
        IServiceProvider services,
        ILogger<ScanWorker> logger)
    {
        _coordinator = coordinator;
        _store = store;
        _progress = progress;
        _logger = logger;
        _loggerFactory = services.GetRequiredService<ILoggerFactory>();
        _pingTool = new PingScanTool(_loggerFactory.CreateLogger<PingScanTool>());
        _portTool = new PortScanTool(_loggerFactory.CreateLogger<PortScanTool>());
        _udpTool = new UdpScanTool(_loggerFactory.CreateLogger<UdpScanTool>());
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ScanWorker 启动，等待扫描任务");
        await _store.MarkStaleTasksFailedAsync("服务重启，未完成的任务已标记失败");

        await foreach (var req in _coordinator.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await _gate.WaitAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                await _store.MarkFailedAsync(req.TaskId, "服务关闭，任务未执行");
                throw;
            }
            try
            {
                await ExecuteOneAsync(req, stoppingToken);
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _coordinator.Complete();
        await base.StopAsync(cancellationToken);
    }

    private async Task ExecuteOneAsync(ScanJob req, CancellationToken ct)
    {
        _logger.LogInformation("执行扫描: TaskId={TaskId}, Target={Target}, Type={Type}",
            req.TaskId, req.Target, req.ScanType);
        var startedAt = DateTime.UtcNow;
        await _store.MarkRunningAsync(req.TaskId);
        await PublishAsync(req.TaskId, "running", "任务开始", 5, ct);

        try
        {
            var lf = _loggerFactory;
            var outcome = req.ScanType.ToLowerInvariant() switch
            {
                "ping" => await RunPingAsync(req, startedAt, lf, ct),
                "tcp" => await RunTcpAsync(req, startedAt, lf, ct),
                "udp" => await RunUdpAsync(req, startedAt, lf, ct),
                var other => new ScanOutcome(null, 0, $"不支持的扫描类型: {other}"),
            };

            if (outcome.Error != null)
            {
                await _store.MarkFailedAsync(req.TaskId, outcome.Error);
                await PublishAsync(req.TaskId, "failed", outcome.Error, 100, ct);
                _logger.LogWarning("扫描失败: TaskId={TaskId}, Error={Error}", req.TaskId, outcome.Error);
                return;
            }

            var resultJson = outcome.ResultJson
                ?? throw new InvalidOperationException("扫描成功但缺少结果");
            await _store.MarkCompletedAsync(req.TaskId, outcome.TotalDevices, resultJson);
            await PublishAsync(req.TaskId, "completed", "扫描完成", 100, ct, resultJson);
            _logger.LogInformation("扫描完成: TaskId={TaskId}, Alive={Alive}",
                req.TaskId, outcome.TotalDevices);
        }
        catch (OperationCanceledException)
        {
            await _store.MarkFailedAsync(req.TaskId, "扫描被取消");
            await PublishAsync(req.TaskId, "failed", "扫描被取消", 100, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "扫描异常: TaskId={TaskId}", req.TaskId);
            await _store.MarkFailedAsync(req.TaskId, ex.Message);
            await PublishAsync(req.TaskId, "failed", ex.Message, 100, CancellationToken.None);
        }
    }

    private async Task<ScanOutcome> RunPingAsync(
        ScanJob req, DateTime startedAt, ILoggerFactory lf, CancellationToken ct)
    {
        var pingResult = await _pingTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = req.Target,
            ["timeout_ms"] = "3000",
            ["concurrency"] = "50",
        }, ct);

        if (!pingResult.Success)
            return new ScanOutcome(null, 0, pingResult.Error ?? "存活扫描失败");

        await PublishAsync(req.TaskId, "running", "存活扫描完成", 40, ct);

        var totalDevices = 0;
        var discovered = new List<string>();
        var openPortsByIp = new Dictionary<string, int[]>();
        try
        {
            using var doc = JsonDocument.Parse(pingResult.Data);
            var root = doc.RootElement;
            totalDevices = root.TryGetProperty("alive", out var alive) ? alive.GetInt32() : 0;

            if (root.TryGetProperty("devices", out var devices))
            {
                discovered.AddRange(devices.EnumerateArray()
                    .Select(x => x.GetString())
                    .Where(x => !string.IsNullOrEmpty(x))
                    .Cast<string>());

                var candidates = devices.EnumerateArray().Take(5).ToArray();
                for (var i = 0; i < candidates.Length; i++)
                {
                    var ip = candidates[i].GetString();
                    if (string.IsNullOrEmpty(ip)) continue;

                    await PublishAsync(req.TaskId, "running",
                        $"端口识别 {i + 1}/{candidates.Length}", 40 + 10 * (i + 1), ct);

                    var portResult = await _portTool.ExecuteAsync(new ToolArguments
                    {
                        ["target"] = ip,
                        ["ports"] = "22,80,443,3389,8080,8443",
                        ["timeout_ms"] = "2000",
                        ["concurrency"] = "20",
                    }, ct);

                    if (portResult.Success)
                    {
                        using var pdoc = JsonDocument.Parse(portResult.Data);
                        var ports = pdoc.RootElement.TryGetProperty("openPorts", out var p)
                            ? p.EnumerateArray().Select(x => x.GetInt32()).ToArray()
                            : [];
                        openPortsByIp[ip] = ports;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "解析存活扫描结果失败: TaskId={TaskId}", req.TaskId);
        }

        var resultJson = JsonSerializer.Serialize(new
        {
            target = req.Target,
            scanType = "ping",
            alive = totalDevices,
            devices = discovered.ToArray(),
            openPortsByIp,
            durationSec = Math.Round((DateTime.UtcNow - startedAt).TotalSeconds, 2),
        });

        return new ScanOutcome(resultJson, totalDevices);
    }

    private async Task<ScanOutcome> RunTcpAsync(
        ScanJob req, DateTime startedAt, ILoggerFactory lf, CancellationToken ct)
    {
        await PublishAsync(req.TaskId, "running", "TCP 扫描进行中", 50, ct);
        var result = await _portTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = req.Target,
            ["ports"] = string.IsNullOrWhiteSpace(req.Ports) ? "1-1000" : req.Ports,
            ["timeout_ms"] = "5000",
            ["concurrency"] = "50",
        }, ct);

        if (!result.Success)
            return new ScanOutcome(null, 0, result.Error ?? "TCP 扫描失败");

        return BuildPortOutcome(req, startedAt, result.Data, "tcp");
    }

    private async Task<ScanOutcome> RunUdpAsync(
        ScanJob req, DateTime startedAt, ILoggerFactory lf, CancellationToken ct)
    {
        await PublishAsync(req.TaskId, "running", "UDP 扫描进行中", 50, ct);
        var result = await _udpTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = req.Target,
            ["ports"] = string.IsNullOrWhiteSpace(req.Ports) ? "1-1000" : req.Ports,
            ["timeout_ms"] = "3000",
            ["concurrency"] = "50",
        }, ct);

        if (!result.Success)
            return new ScanOutcome(null, 0, result.Error ?? "UDP 扫描失败");

        return BuildPortOutcome(req, startedAt, result.Data, "udp");
    }

    private static ScanOutcome BuildPortOutcome(
        ScanJob req, DateTime startedAt, string data, string scanType)
    {
        var totalScanned = 0;
        var openPorts = Array.Empty<int>();
        try
        {
            using var doc = JsonDocument.Parse(data);
            var root = doc.RootElement;
            totalScanned = root.TryGetProperty("totalScanned", out var total) ? total.GetInt32() : 0;
            if (root.TryGetProperty("openPorts", out var ports))
                openPorts = ports.EnumerateArray().Select(x => x.GetInt32()).ToArray();
        }
        catch (JsonException ex)
        {
            return new ScanOutcome(null, 0, $"扫描结果解析失败: {ex.Message}");
        }

        var resultJson = JsonSerializer.Serialize(new
        {
            target = req.Target,
            scanType,
            totalScanned,
            openPorts,
            durationSec = Math.Round((DateTime.UtcNow - startedAt).TotalSeconds, 2),
        });

        return new ScanOutcome(resultJson, 0);
    }

    private async Task PublishAsync(
        string taskId, string status, string message, int percent,
        CancellationToken ct, string? resultJson = null)
    {
        try
        {
            await _progress.PublishAsync(
                new ScanProgressEvent(taskId, status, message, percent, resultJson), ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "推送扫描进度失败: TaskId={TaskId}", taskId);
        }
    }

    private sealed record ScanOutcome(string? ResultJson, int TotalDevices, string? Error = null);
}
