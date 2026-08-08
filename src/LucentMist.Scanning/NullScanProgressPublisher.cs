namespace LucentMist.Scanning;

/// <summary>无推送通道时使用的空实现。</summary>
public sealed class NullScanProgressPublisher : IScanProgressPublisher
{
    public static readonly NullScanProgressPublisher Instance = new();

    public Task PublishAsync(ScanProgressEvent evt, CancellationToken ct = default)
        => Task.CompletedTask;
}
