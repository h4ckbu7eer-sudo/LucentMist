using System.Threading.Channels;

namespace LucentMist.Scanning;

/// <summary>
/// 基于 Channel 的扫描任务队列。StartAsync 入队立即返回，ScanWorker 后台消费。
/// </summary>
public class ScanCoordinator : IScanCoordinator
{
    private readonly Channel<ScanJob> _channel;
    private readonly ScanStore _store;

    public ScanCoordinator(ScanStore store, int capacity = 32)
    {
        _store = store;
        _channel = Channel.CreateBounded<ScanJob>(
            new BoundedChannelOptions(capacity)
            {
                // StartAsync 使用 TryWrite 显式拒绝；不要改用会无限等待的 WriteAsync。
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });
    }

    /// <summary>仅供 ScanWorker 读取队列。</summary>
    public ChannelReader<ScanJob> Reader => _channel.Reader;

    public void Complete() => _channel.Writer.TryComplete();

    public async Task<string> StartAsync(
        string target,
        string scanType = "ping",
        string ports = "",
        CancellationToken ct = default)
    {
        var rec = await _store.CreateAsync(target, scanType, ports);
        if (!_channel.Writer.TryWrite(new ScanJob(rec.Id, target, scanType, ports)))
        {
            try { await _store.MarkFailedAsync(rec.Id, "扫描队列已满，请稍后重试"); }
            catch { /* 保留队列已满错误 */ }
            throw new ScanQueueFullException("扫描队列已满，请稍后重试");
        }
        return rec.Id;
    }
}

public sealed class ScanQueueFullException : Exception
{
    public ScanQueueFullException(string message) : base(message) { }
}
