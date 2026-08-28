using LucentMist.Scanning;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Data.Sqlite;

namespace LucentMist.Web;

/// <summary>
/// 扫描任务客户端：提交任务、订阅 SignalR 进度，并以 SQLite 轮询兜底，
/// 避免连接尚未加入分组时任务已经完成导致丢事件。
/// </summary>
public sealed class ScanTaskClient : IAsyncDisposable
{
    private readonly IScanCoordinator _coordinator;
    private readonly IScanTaskReader _store;
    private readonly NavigationManager _navigation;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly bool _enableSignalR;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly SemaphoreSlim _hubGate = new(1, 1);
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private readonly object _stateGate = new();
    private readonly HashSet<Task> _pollTasks = [];
    private HubConnection? _hub;
    private ActiveRun? _activeRun;
    private string _taskId = "";
    private bool _disposed;

    public ScanTaskClient(
        IScanCoordinator coordinator,
        IScanTaskReader store,
        NavigationManager navigation)
        : this(coordinator, store, navigation, Task.Delay, true)
    {
    }

    internal ScanTaskClient(
        IScanCoordinator coordinator,
        IScanTaskReader store,
        NavigationManager navigation,
        Func<TimeSpan, CancellationToken, Task> delay,
        bool enableSignalR)
    {
        _coordinator = coordinator;
        _store = store;
        _navigation = navigation;
        _delay = delay;
        _enableSignalR = enableSignalR;
    }

    public string TaskId => _taskId;
    public string CurrentTaskId => _taskId;
    public string CurrentStatus { get; private set; } = "";
    public string CurrentMessage { get; private set; } = "";
    public int ProgressPercent { get; private set; }
    public string? LastError { get; private set; }
    public string? MonitoringError { get; private set; }

    public void SetStartupError(string error)
    {
        lock (_stateGate)
        {
            if (_activeRun is { FinalRaised: false })
            {
                MonitoringError = error;
                return;
            }

            _taskId = "";
            CurrentStatus = "failed";
            CurrentMessage = "失败";
            ProgressPercent = 0;
            LastError = error;
            MonitoringError = null;
        }
    }

    public event Action<ScanProgressEvent>? Progress;
    public event Action<ScanTaskRecord>? Completed;
    public event Action<string, string>? Failed;

    public async Task<string> StartAsync(
        string target, string scanType, string ports, CancellationToken ct = default)
    {
        await _lifecycleGate.WaitAsync(ct);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            // Queue first. A rejected start must not invalidate the task currently shown.
            var taskId = await _coordinator.StartAsync(target, scanType, ports, ct);
            var run = new ActiveRun(taskId, target, scanType, ports, _disposeCts.Token);
            ActiveRun? previous;

            lock (_stateGate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                previous = _activeRun;
                _activeRun = run;
                _taskId = taskId;
                CurrentStatus = "pending";
                CurrentMessage = "等待队列";
                ProgressPercent = 0;
                LastError = null;
                MonitoringError = null;
            }

            previous?.Cancel();
            run.PollTask = PollUntilFinalAsync(run);
            TrackPollTask(run);

            if (_enableSignalR)
                await TryJoinHubAsync(previous?.TaskId, run);
            return taskId;
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    private async Task<HubConnection> GetHubAsync(CancellationToken ct)
    {
        await _hubGate.WaitAsync(ct);
        try
        {
            if (_hub is { State: not HubConnectionState.Disconnected }) return _hub;

            if (_hub is null)
            {
                _hub = new HubConnectionBuilder()
                    .WithUrl(_navigation.ToAbsoluteUri("/scanhub"))
                    .WithAutomaticReconnect()
                    .Build();

                _hub.Reconnected += _ => RejoinScanGroupAsync();

                _hub.On<ScanProgressEvent>("ScanProgress", evt =>
                {
                    ActiveRun? run;
                    lock (_stateGate)
                    {
                        run = _activeRun;
                        if (_disposed || run is null || run.FinalRaised ||
                            evt.TaskId != run.TaskId)
                            return;

                        CurrentStatus = evt.Status;
                        CurrentMessage = evt.Message;
                        ProgressPercent = evt.Percent;
                        MonitoringError = null;
                    }

                    Progress?.Invoke(evt);
                    if (evt.Status is "completed" or "failed")
                    {
                        if (evt.Status == "completed")
                            RaiseFinal(run, new ScanTaskRecord
                            {
                                Id = run.TaskId,
                                Target = run.Target,
                                ScanType = run.ScanType,
                                Ports = run.Ports,
                                Status = "completed",
                                ResultJson = evt.ResultJson
                            });
                        else
                            RaiseFinal(run, null, evt.Message);
                    }
                });
            }

            await _hub.StartAsync(ct);
            return _hub;
        }
        finally
        {
            _hubGate.Release();
        }
    }

    private async Task TryJoinHubAsync(string? previousTaskId, ActiveRun run)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                run.Token, _disposeCts.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            var hub = await GetHubAsync(timeout.Token);
            if (!string.IsNullOrEmpty(previousTaskId))
                await hub.InvokeAsync("LeaveScanGroup", previousTaskId, timeout.Token);
            if (IsActive(run))
                await hub.InvokeAsync("JoinScanGroup", run.TaskId, timeout.Token);
        }
        catch (OperationCanceledException) when (
            _disposeCts.IsCancellationRequested || run.Token.IsCancellationRequested)
        {
            // The run was replaced or the client was disposed.
        }
        catch (Exception ex)
        {
            SetMonitoringError(run, ex.Message);
        }
    }

    private async Task RejoinScanGroupAsync()
    {
        ActiveRun? run;
        lock (_stateGate)
            run = _disposed ? null : _activeRun;
        if (run is null || run.FinalRaised || _hub is null) return;

        try
        {
            await _hub.InvokeAsync("JoinScanGroup", run.TaskId, run.Token);
        }
        catch (Exception ex)
        {
            SetMonitoringError(run, ex.Message);
        }
    }

    private async Task PollUntilFinalAsync(ActiveRun run)
    {
        var transientAttempt = 0;
        try
        {
            while (!run.Token.IsCancellationRequested && IsActive(run))
            {
                try
                {
                    var rec = await _store.GetAsync(run.TaskId);
                    transientAttempt = 0;
                    if (rec is null)
                    {
                        SetMonitoringError(run, "暂时无法读取扫描任务状态");
                        await _delay(TimeSpan.FromSeconds(1), run.Token);
                        continue;
                    }

                    SetMonitoringError(run, null);
                    if (rec.Status == "completed")
                    {
                        RaiseFinal(run, rec);
                        return;
                    }

                    if (rec.Status == "failed")
                    {
                        RaiseFinal(run, null, rec.ErrorMessage ?? "扫描失败");
                        return;
                    }

                    await _delay(TimeSpan.FromMilliseconds(500), run.Token);
                }
                catch (SqliteException ex) when (IsTransientSqlite(ex))
                {
                    transientAttempt++;
                    SetMonitoringError(run, "数据库繁忙，正在重试状态读取");
                    var delayMs = Math.Min(1000, 100 * (1 << Math.Min(3, transientAttempt - 1)));
                    await _delay(TimeSpan.FromMilliseconds(delayMs), run.Token);
                }
                catch (OperationCanceledException) when (run.Token.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    SetMonitoringError(run, ex.Message);
                    await _delay(TimeSpan.FromSeconds(1), run.Token);
                }
            }
        }
        catch (OperationCanceledException) when (run.Token.IsCancellationRequested)
        {
            // The run was replaced or the client was disposed.
        }
    }

    private static bool IsTransientSqlite(SqliteException ex) =>
        ex.SqliteErrorCode is 5 or 6;

    private void RaiseFinal(ActiveRun run, ScanTaskRecord? rec, string? error = null)
    {
        Action<ScanTaskRecord>? completed = null;
        Action<string, string>? failed = null;
        string? failure = null;

        lock (_stateGate)
        {
            if (_disposed || !ReferenceEquals(_activeRun, run) || run.FinalRaised)
                return;

            run.FinalRaised = true;
            run.Cancel();
            ProgressPercent = 100;
            MonitoringError = null;

            if (rec is { Status: "completed" } && rec.ResultJson is not null)
            {
                CurrentStatus = "completed";
                CurrentMessage = "完成";
                LastError = null;
                completed = Completed;
            }
            else
            {
                CurrentStatus = "failed";
                CurrentMessage = "失败";
                failure = error ?? "扫描未完成";
                LastError = failure;
                failed = Failed;
            }
        }

        if (completed is not null && rec is not null)
            completed(rec);
        else if (failed is not null && failure is not null)
            failed(run.TaskId, failure);
    }

    public async ValueTask DisposeAsync()
    {
        await _lifecycleGate.WaitAsync();
        try
        {
            lock (_stateGate)
            {
                if (_disposed) return;
                _disposed = true;
                _activeRun?.Cancel();
            }

            _disposeCts.Cancel();
            Task[] polls;
            lock (_pollTasks)
                polls = [.. _pollTasks];
            try
            {
                await Task.WhenAll(polls);
            }
            catch (OperationCanceledException)
            {
                // Expected while active runs are being torn down.
            }

            if (_hub is not null)
            {
                await _hub.DisposeAsync();
                _hub = null;
            }
            _disposeCts.Dispose();
            _hubGate.Dispose();
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    private bool IsActive(ActiveRun run)
    {
        lock (_stateGate)
            return !_disposed && ReferenceEquals(_activeRun, run) && !run.FinalRaised;
    }

    private void SetMonitoringError(ActiveRun run, string? error)
    {
        lock (_stateGate)
        {
            if (!_disposed && ReferenceEquals(_activeRun, run) && !run.FinalRaised)
                MonitoringError = error;
        }
    }

    private void TrackPollTask(ActiveRun run)
    {
        var task = run.PollTask
            ?? throw new InvalidOperationException("Polling task has not been initialized.");
        lock (_pollTasks)
            _pollTasks.Add(task);

        _ = task.ContinueWith(
            completed =>
            {
                lock (_pollTasks)
                    _pollTasks.Remove(completed);
                run.Dispose();
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private sealed class ActiveRun : IDisposable
    {
        private readonly CancellationTokenSource _cts;

        public ActiveRun(
            string taskId,
            string target,
            string scanType,
            string ports,
            CancellationToken disposeToken)
        {
            TaskId = taskId;
            Target = target;
            ScanType = scanType;
            Ports = ports;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(disposeToken);
        }

        public string TaskId { get; }
        public string Target { get; }
        public string ScanType { get; }
        public string Ports { get; }
        public CancellationToken Token => _cts.Token;
        public Task? PollTask { get; set; }
        public bool FinalRaised { get; set; }

        public void Cancel()
        {
            if (!_cts.IsCancellationRequested)
                _cts.Cancel();
        }

        public void Dispose() => _cts.Dispose();
    }
}
