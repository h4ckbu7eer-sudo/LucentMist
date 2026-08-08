using LucentMist.Scanning;
using LucentMist.Web.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace LucentMist.Web;

/// <summary>把扫描进度推送到 ScanHub 的对应任务分组。</summary>
public sealed class SignalRScanProgressPublisher : IScanProgressPublisher
{
    private readonly IHubContext<ScanHub> _hub;

    public SignalRScanProgressPublisher(IHubContext<ScanHub> hub)
    {
        _hub = hub;
    }

    public async Task PublishAsync(ScanProgressEvent evt, CancellationToken ct = default)
        => await _hub.Clients.Group(evt.TaskId).SendAsync("ScanProgress", evt, ct);
}
