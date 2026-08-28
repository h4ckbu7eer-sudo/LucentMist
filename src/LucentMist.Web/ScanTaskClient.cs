using LucentMist.Scanning;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.SignalR.Client;

namespace LucentMist.Web;

/// <summary>
/// 扫描任务客户端：提交任务、订阅 SignalR 进度，并以 SQLite 轮询兜底，
/// 避免连接尚未加入分组时任务已经完成导致丢事件。
/// </summary>
public sealed class ScanTaskClient : IAsyncDisposable
{
    private readonly IScanCoordinator _coordinator;
    private readonly ScanStore _store;
    private readonly NavigationManager _navigation;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _hubGate = new(1, 1);
    private HubConnection? _hub;
    private Task? _pollTask;
    private string _taskId = "";
    private string _target = "";
    private string _scanType = "";
    private string _ports = "";
    private int _version;
    private int _finalRaised;
    private bool _disposed;

    public ScanTaskClient(
        IScanCoordinator coordinator,
        ScanStore store,
        NavigationManager navigation)
    {
        _coordinator = coordinator;
        _store = store;
        _navigation = navigation;
    }

    public string TaskId => _taskId;
    public string CurrentTaskId => _taskId;
    public string CurrentStatus { get; private set; } = "";
    public string CurrentMessage { get; private set; } = "";
    public int ProgressPercent { get; private set; }
    public string? LastError { get; private set; }

    public void SetStartupError(string error)
    {
        _taskId = "";
        _target = "";
        _scanType = "";
        _ports = "";
        CurrentStatus = "failed";
        CurrentMessage = "失败";
        ProgressPercent = 0;
        LastError = error;
    }

    public event Action<ScanProgressEvent>? Progress;
    public event Action<ScanTaskRecord>? Completed;
    public event Action<string>? Failed;

    public async Task<string> StartAsync(
        string target, string scanType, string ports, CancellationToken ct = default)
    {
        var previousTaskId = _taskId;
        var version = Interlocked.Increment(ref _version);
        _taskId = await _coordinator.StartAsync(target, scanType, ports, ct);
        _target = target;
        _scanType = scanType;
        _ports = ports;
        _finalRaised = 0;
        CurrentStatus = "pending";
        CurrentMessage = "等待队列";
        ProgressPercent = 0;
        LastError = null;
        _pollTask = PollUntilFinalAsync(_taskId, version);
        await TryJoinHubAsync(previousTaskId);
        return _taskId;
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
                    if (evt.TaskId != _taskId) return;
                    CurrentStatus = evt.Status;
                    CurrentMessage = evt.Message;
                    ProgressPercent = evt.Percent;
                    Progress?.Invoke(evt);
                    if (evt.Status is "completed" or "failed")
                    {
                        if (evt.Status == "completed")
                            RaiseFinal(new ScanTaskRecord
                            {
                                Id = _taskId,
                                Target = _target,
                                ScanType = _scanType,
                                Ports = _ports,
                                Status = "completed",
                                ResultJson = evt.ResultJson
                            });
                        else
                            RaiseFinal(null, evt.Message);
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

    private async Task TryJoinHubAsync(string previousTaskId)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            var hub = await GetHubAsync(timeout.Token);
            if (!string.IsNullOrEmpty(previousTaskId))
                await hub.InvokeAsync("LeaveScanGroup", previousTaskId, timeout.Token);
            await hub.InvokeAsync("JoinScanGroup", _taskId, timeout.Token);
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            // Client disposed; polling is stopping as well.
        }
        catch
        {
            // SignalR is an optimization. SQLite polling remains the source of truth.
        }
    }

    private async Task RejoinScanGroupAsync()
    {
        if (_disposed || _hub is null || string.IsNullOrEmpty(_taskId)) return;

        try
        {
            await _hub.InvokeAsync("JoinScanGroup", _taskId);
        }
        catch
        {
            // The client keeps its polling fallback, so a failed rejoin is not fatal.
        }
    }

    private async Task PollUntilFinalAsync(string taskId, int version)
    {
        try
        {
            while (!_cts.IsCancellationRequested &&
                   version == Volatile.Read(ref _version))
            {
                var rec = await _store.GetAsync(taskId);
                if (rec is null) return;
                if (rec.Status is "completed" or "failed")
                {
                    if (version != Volatile.Read(ref _version)) return;
                    if (rec.Status == "completed")
                        RaiseFinal(rec);
                    else
                        RaiseFinal(null, rec.ErrorMessage ?? "扫描失败");
                    return;
                }

                await Task.Delay(500, _cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Page or client disposed; the polling task is expected to stop.
        }
        catch (Exception ex)
        {
            if (_disposed) return;
            RaiseFinal(null, ex.Message);
        }
    }

    private void RaiseFinal(ScanTaskRecord? rec, string? error = null)
    {
        if (Interlocked.Exchange(ref _finalRaised, 1) == 1) return;

        if (rec is { Status: "completed" } && rec.ResultJson is not null)
        {
            CurrentStatus = "completed";
            CurrentMessage = "完成";
            ProgressPercent = 100;
            LastError = null;
            Completed?.Invoke(rec);
        }
        else
        {
            CurrentStatus = "failed";
            CurrentMessage = "失败";
            ProgressPercent = 100;
            LastError = error ?? "扫描未完成";
            Failed?.Invoke(LastError);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        if (_pollTask is not null)
        {
            try
            {
                await _pollTask;
            }
            catch
            {
                // Polling is best-effort and is being torn down.
            }
        }
        if (_hub is not null)
        {
            await _hub.DisposeAsync();
            _hub = null;
        }
        _cts.Dispose();
        _hubGate.Dispose();
    }
}
