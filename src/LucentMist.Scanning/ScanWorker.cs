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
        try
        {
            await _store.MarkStaleTasksFailedAsync(
                "服务重启，未收到心跳的旧任务已标记失败",
                TimeSpan.FromMinutes(2));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "启动时清理陈旧任务失败，继续运行");
        }

        await foreach (var req in _coordinator.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await ExecuteOneAsync(req, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                await TryMarkFailedAsync(req.TaskId, "服务关闭，任务未执行");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "扫描任务执行崩溃: TaskId={TaskId}", req.TaskId);
                await TryMarkFailedAsync(req.TaskId, ex.Message);
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _coordinator.Complete();
        try
        {
            await base.StopAsync(cancellationToken);
        }
        finally
        {
            while (_coordinator.Reader.TryRead(out var pending))
                await TryMarkFailedAsync(pending.TaskId, "服务关闭，队列中的任务未执行");
        }
    }

    private async Task TryMarkFailedAsync(string taskId, string error)
    {
        try
        {
            await _store.MarkFailedAsync(taskId, error);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "标记任务失败时再次出错: TaskId={TaskId}", taskId);
        }
    }

    private async Task ExecuteOneAsync(ScanJob req, CancellationToken ct)
    {
        _logger.LogInformation("执行扫描: TaskId={TaskId}, Target={Target}, Type={Type}",
            req.TaskId, req.Target, req.ScanType);
        var startedAt = DateTime.UtcNow;
        if (!await _store.MarkRunningAsync(req.TaskId))
        {
            _logger.LogWarning("任务已进入终态或不存在，跳过执行: TaskId={TaskId}", req.TaskId);
            return;
        }
        await PublishAsync(req.TaskId, "running", "任务开始", 5, ct);

        using var heartbeatCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var heartbeatTask = HeartbeatAsync(req.TaskId, heartbeatCts.Token);

        try
        {
            var outcome = req.ScanType.ToLowerInvariant() switch
            {
                "ping" => await RunPingAsync(req, startedAt, ct),
                "tcp" => await RunTcpAsync(req, startedAt, ct),
                "udp" => await RunUdpAsync(req, startedAt, ct),
                var other => new ScanOutcome(null, 0, $"不支持的扫描类型: {other}"),
            };

            if (outcome.Error != null)
            {
                if (await _store.MarkFailedAsync(req.TaskId, outcome.Error))
                    await PublishTerminalAsync(req.TaskId, "failed", outcome.Error);
                _logger.LogWarning("扫描失败: TaskId={TaskId}, Error={Error}", req.TaskId, outcome.Error);
                return;
            }

            var resultJson = outcome.ResultJson
                ?? throw new InvalidOperationException("扫描成功但缺少结果");
            await PersistCompletedAndPublishAsync(
                req.TaskId, outcome.TotalDevices, resultJson);
            _logger.LogInformation("扫描完成: TaskId={TaskId}, Alive={Alive}",
                req.TaskId, outcome.TotalDevices);
        }
        catch (OperationCanceledException)
        {
            if (await _store.MarkFailedAsync(req.TaskId, "扫描被取消"))
                await PublishTerminalAsync(req.TaskId, "failed", "扫描被取消");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "扫描异常: TaskId={TaskId}", req.TaskId);
            if (await _store.MarkFailedAsync(req.TaskId, ex.Message))
                await PublishTerminalAsync(req.TaskId, "failed", ex.Message);
        }
        finally
        {
            heartbeatCts.Cancel();
            try
            {
                await heartbeatTask;
            }
            catch
            {
                // Heartbeat is best-effort and stops with the scan.
            }
        }
    }

    private async Task<ScanOutcome> RunPingAsync(
        ScanJob req, DateTime startedAt, CancellationToken ct)
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
        var openPortsByIp = new System.Collections.Concurrent.ConcurrentDictionary<string, int[]>();
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

                var candidates = devices.EnumerateArray()
                    .Take(5)
                    .Select(item => item.GetString())
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Cast<string>()
                    .ToArray();
                var identified = 0;
                await Parallel.ForEachAsync(
                    candidates,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = Math.Min(3, Math.Max(1, candidates.Length)),
                        CancellationToken = ct,
                    },
                    async (ip, token) =>
                    {
                        var portResult = await _portTool.ExecuteAsync(new ToolArguments
                        {
                            ["target"] = ip,
                            ["ports"] = "22,80,443,3389,8080,8443",
                            ["timeout_ms"] = "2000",
                            ["concurrency"] = "20",
                        }, token);

                        if (portResult.Success)
                        {
                            using var pdoc = JsonDocument.Parse(portResult.Data);
                            var ports = pdoc.RootElement.TryGetProperty("openPorts", out var p)
                                ? p.EnumerateArray().Select(x => x.GetInt32()).ToArray()
                                : [];
                            openPortsByIp[ip] = ports;
                        }

                        var done = Interlocked.Increment(ref identified);
                        await PublishAsync(req.TaskId, "running",
                            $"端口识别 {done}/{candidates.Length}",
                            40 + 10 * done,
                            token);
                    });
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

    private async Task HeartbeatAsync(string taskId, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
                await _store.MarkHeartbeatAsync(taskId);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "扫描心跳更新失败: TaskId={TaskId}", taskId);
            }
        }
    }

    private async Task<ScanOutcome> RunTcpAsync(
        ScanJob req, DateTime startedAt, CancellationToken ct)
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
        ScanJob req, DateTime startedAt, CancellationToken ct)
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

    internal async Task PersistCompletedAndPublishAsync(
        string taskId,
        int totalDevices,
        string resultJson)
    {
        if (!await _store.MarkCompletedAsync(taskId, totalDevices, resultJson))
        {
            _logger.LogWarning("任务已进入其他终态，忽略完成结果: TaskId={TaskId}", taskId);
            return;
        }

        await PublishTerminalAsync(taskId, "completed", "扫描完成", resultJson);
    }

    private async Task PublishTerminalAsync(
        string taskId,
        string status,
        string message,
        string? resultJson = null)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await _progress.PublishAsync(
                new ScanProgressEvent(taskId, status, message, 100, resultJson),
                timeout.Token);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning(
                "终态已持久化，但进度通知超时或被取消: TaskId={TaskId}, Status={Status}",
                taskId,
                status);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "终态已持久化，但进度通知失败: TaskId={TaskId}, Status={Status}",
                taskId,
                status);
        }
    }

    private sealed record ScanOutcome(string? ResultJson, int TotalDevices, string? Error = null);
}
