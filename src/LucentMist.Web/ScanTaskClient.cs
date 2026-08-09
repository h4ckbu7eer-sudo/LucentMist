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
    private HubConnection? _hub;
    private string _taskId = "";
    private int _finalRaised;

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

    public event Action<ScanProgressEvent>? Progress;
    public event Action<ScanTaskRecord>? Completed;
    public event Action<string>? Failed;

    public async Task<string> StartAsync(
        string target, string scanType, string ports, CancellationToken ct = default)
    {
        var hub = await GetHubAsync(ct);
        _taskId = await _coordinator.StartAsync(target, scanType, ports, ct);
        _finalRaised = 0;
        _ = PollUntilFinalAsync();
        await hub.InvokeAsync("JoinScanGroup", _taskId, ct);
        return _taskId;
    }

    private async Task<HubConnection> GetHubAsync(CancellationToken ct)
    {
        if (_hub is not null) return _hub;

        _hub = new HubConnectionBuilder()
            .WithUrl(_navigation.ToAbsoluteUri("/scanhub"))
            .WithAutomaticReconnect()
            .Build();

        _hub.On<ScanProgressEvent>("ScanProgress", evt =>
        {
            if (evt.TaskId != _taskId) return;
            Progress?.Invoke(evt);
            if (evt.Status is "completed" or "failed")
            {
                if (evt.Status == "completed")
                    RaiseFinal(new ScanTaskRecord { Id = _taskId, Status = "completed", ResultJson = evt.ResultJson });
                else
                    RaiseFinal(null, evt.Message);
            }
        });

        await _hub.StartAsync(ct);
        return _hub;
    }

    private async Task PollUntilFinalAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var rec = await _store.GetAsync(_taskId);
                if (rec is null) return;
                if (rec.Status is "completed" or "failed")
                {
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
            // 页面已关闭，正常结束。
        }
        catch (Exception ex)
        {
            RaiseFinal(null, ex.Message);
        }
    }

    private void RaiseFinal(ScanTaskRecord? rec, string? error = null)
    {
        if (Interlocked.Exchange(ref _finalRaised, 1) == 1) return;

        if (rec is { Status: "completed" } && rec.ResultJson is not null)
            Completed?.Invoke(rec);
        else
            Failed?.Invoke(error ?? "扫描未完成");
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_hub is not null)
        {
            await _hub.DisposeAsync();
            _hub = null;
        }
        _cts.Dispose();
    }
}
