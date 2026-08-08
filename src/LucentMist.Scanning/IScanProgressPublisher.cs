namespace LucentMist.Scanning;

/// <summary>扫描进度发布接口，宿主可接入 SignalR、WebSocket 或日志。</summary>
public interface IScanProgressPublisher
{
    Task PublishAsync(ScanProgressEvent evt, CancellationToken ct = default);
}
