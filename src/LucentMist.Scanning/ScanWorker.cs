using System.Text.Json;
using System.Text.Json.Nodes;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LucentMist.Scanning;

/// <summary>
/// 后台扫描 worker — 从 Channel 消费任务，调用真实扫描工具，状态落 SQLite 并推送进度。
/// 默认最多并发 2 个扫描，避免慢 ping 队头阻塞，同时限制网络资源放大。
/// </summary>
public sealed class ScanWorker : BackgroundService
{
    private readonly ScanCoordinator _coordinator;
    private readonly ScanStore _store;
    private readonly IScanProgressPublisher _progress;
    private readonly ILogger<ScanWorker> _logger;
    private readonly ILoggerFactory _loggerFactory;

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

        await BoundedScanDispatcher.RunAsync(
            _coordinator.Reader,
            ExecuteQueuedJobAsync,
            GetWorkerConcurrency(),
            stoppingToken);
    }

    private async Task ExecuteQueuedJobAsync(ScanJob req, CancellationToken stoppingToken)
    {
        try
        {
            await ExecuteOneAsync(req, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            await TryMarkFailedAsync(req, "服务关闭，任务未执行", "canceled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "扫描任务执行崩溃: TaskId={TaskId}", req.TaskId);
            await TryMarkFailedAsync(req, "扫描执行异常");
        }
    }

    private static int GetWorkerConcurrency() =>
        int.TryParse(Environment.GetEnvironmentVariable("LMIST_SCAN_WORKER_CONCURRENCY"), out var configured)
            ? Math.Clamp(configured, 1, 3)
            : 2;

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
                await TryMarkFailedAsync(pending, "服务关闭，队列中的任务未执行", "canceled");
        }
    }

    private async Task TryMarkFailedAsync(
        ScanJob job,
        string error,
        string auditStatus = "failed")
    {
        try
        {
            if (await _store.MarkFailedAsync(job.TaskId, error))
            {
                await _store.AppendAuditAsync(
                    job.TaskId,
                    job.TaskId,
                    job.Target,
                    job.Initiator,
                    job.ScanType,
                    auditStatus,
                    error);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "标记任务失败时再次出错: TaskId={TaskId}", job.TaskId);
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
                {
                    await AppendAuditTerminalAsync(req, "failed", outcome.Error);
                    await PublishTerminalAsync(req.TaskId, "failed", outcome.Error);
                }
                _logger.LogWarning("扫描失败: TaskId={TaskId}, Error={Error}", req.TaskId, outcome.Error);
                return;
            }

            var resultJson = outcome.ResultJson
                ?? throw new InvalidOperationException("扫描成功但缺少结果");
            await PersistCompletedAndPublishAsync(
                req.TaskId, outcome.TotalDevices, resultJson, req);
            _logger.LogInformation("扫描完成: TaskId={TaskId}, Alive={Alive}",
                req.TaskId, outcome.TotalDevices);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            if (await _store.MarkFailedAsync(req.TaskId, "扫描被取消"))
            {
                await AppendAuditTerminalAsync(req, "canceled", "扫描被取消");
                await PublishTerminalAsync(req.TaskId, "failed", "扫描被取消");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "扫描异常: TaskId={TaskId}", req.TaskId);
            if (await _store.MarkFailedAsync(req.TaskId, ex.Message))
            {
                await AppendAuditTerminalAsync(req, "failed", "扫描执行异常");
                await PublishTerminalAsync(req.TaskId, "failed", ex.Message);
            }
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

    internal async Task<ScanOutcome> RunPingAsync(
        ScanJob req, DateTime startedAt, CancellationToken ct, ITool? pingTool = null, ITool? portTool = null)
    {
        pingTool ??= new PingScanTool(_loggerFactory.CreateLogger<PingScanTool>());
        portTool ??= new PortScanTool(_loggerFactory.CreateLogger<PortScanTool>());
        var pingResult = await pingTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = req.Target,
            ["timeout_ms"] = "3000",
            ["concurrency"] = "50",
        }, ct);

        if (!pingResult.Success)
            return new ScanOutcome(null, 0, pingResult.Error ?? "存活扫描失败");

        await PublishAsync(req.TaskId, "running", "存活扫描完成", 40, ct);

        JsonObject snapshot;
        string[] discovered;
        try
        {
            snapshot = JsonNode.Parse(pingResult.Data) as JsonObject ?? throw new JsonException("Expected object");
            using var doc = JsonDocument.Parse(pingResult.Data);
            discovered = doc.RootElement.GetProperty("devices").EnumerateArray()
                .Select(ip => ip.GetString() ?? throw new JsonException("Null device address")).ToArray();
            if (doc.RootElement.GetProperty("alive").GetInt32() != discovered.Length)
                throw new JsonException("Device count does not match evidence");
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            _logger.LogWarning(ex, "解析存活扫描结果失败: TaskId={TaskId}", req.TaskId);
            return new ScanOutcome(null, 0, "存活扫描结果缺失或格式无效，不能确认发现结果");
        }
        var openPortsByIp = new System.Collections.Concurrent.ConcurrentDictionary<string, int[]>();
        var failures = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
        var candidates = discovered.Take(5).ToArray();
        const string enrichmentPorts = "22,80,443,3389,8080,8443";
        var identified = 0;
        await Parallel.ForEachAsync(candidates, new ParallelOptions { MaxDegreeOfParallelism = 3, CancellationToken = ct }, async (ip, token) =>
        {
            try
            {
                var portResult = await portTool.ExecuteAsync(new ToolArguments
                {
                    ["target"] = ip,
                    ["ports"] = enrichmentPorts,
                    ["timeout_ms"] = "2000",
                    ["concurrency"] = "20",
                }, token);
                if (portResult.Success)
                {
                    using var pdoc = JsonDocument.Parse(portResult.Data);
                    openPortsByIp[ip] = pdoc.RootElement.GetProperty("openPorts").EnumerateArray().Select(p => p.GetInt32()).ToArray();
                }
                else failures[ip] = "端口补充扫描失败，不能判断开放端口";
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "端口补充检查未完成: TaskId={TaskId}, Target={Target}", req.TaskId, ip);
                failures[ip] = "端口补充扫描未完成或结果无效";
            }
            var done = Interlocked.Increment(ref identified);
            await PublishAsync(req.TaskId, "running", $"端口识别 {done}/{candidates.Length}", 40 + 10 * done, token);
        });
        ct.ThrowIfCancellationRequested();
        snapshot["target"] = req.Target;
        snapshot["scanType"] = "ping";
        snapshot["openPortsByIp"] = JsonSerializer.SerializeToNode(openPortsByIp);
        snapshot["portScanFailures"] = JsonSerializer.SerializeToNode(failures);
        snapshot["portScanScope"] = JsonSerializer.SerializeToNode(new { ports = enrichmentPorts, devices = candidates, notScannedDeviceCount = discovered.Length - candidates.Length });
        snapshot["durationSec"] = Math.Round((DateTime.UtcNow - startedAt).TotalSeconds, 2);
        return new ScanOutcome(snapshot.ToJsonString(), discovered.Length);
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
        var portTool = new PortScanTool(_loggerFactory.CreateLogger<PortScanTool>());
        var result = await portTool.ExecuteAsync(new ToolArguments
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
        var udpTool = new UdpScanTool(_loggerFactory.CreateLogger<UdpScanTool>());
        var result = await udpTool.ExecuteAsync(new ToolArguments
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

    internal static ScanOutcome BuildPortOutcome(
        ScanJob req, DateTime startedAt, string data, string scanType)
    {
        try
        {
            using var doc = JsonDocument.Parse(data);
            var root = doc.RootElement;
            var total = root.GetProperty("totalScanned").GetInt32();
            var ports = root.GetProperty("openPorts").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            if (total < 0 || ports.Length > total || ports.Any(p => p is < 1 or > 65535)) throw new JsonException("Invalid port evidence");
            // Keep protocol states, uncertainty explanations and identity evidence.
            // Flattening into openPorts alone silently discards UDP open|filtered.
            var snapshot = JsonNode.Parse(data)!.AsObject();
            snapshot["target"] = req.Target;
            snapshot["scanType"] = scanType;
            snapshot["durationSec"] = Math.Round((DateTime.UtcNow - startedAt).TotalSeconds, 2);
            return new ScanOutcome(snapshot.ToJsonString(), 0);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return new ScanOutcome(null, 0, "扫描结果缺失或格式无效，不能判断开放端口");
        }
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
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
        string resultJson,
        ScanJob? job = null)
    {
        if (!await _store.MarkCompletedAsync(taskId, totalDevices, resultJson))
        {
            _logger.LogWarning("任务已进入其他终态，忽略完成结果: TaskId={TaskId}", taskId);
            return;
        }

        if (job != null)
        {
            await AppendAuditTerminalAsync(
                job,
                "completed",
                $"扫描完成；发现设备 {totalDevices} 台");
        }

        await PublishTerminalAsync(taskId, "completed", "扫描完成", resultJson);
    }

    private Task AppendAuditTerminalAsync(ScanJob job, string status, string summary) =>
        _store.AppendAuditAsync(
            job.TaskId,
            job.TaskId,
            job.Target,
            job.Initiator,
            job.ScanType,
            status,
            summary);

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

    internal sealed record ScanOutcome(string? ResultJson, int TotalDevices, string? Error = null);
}
