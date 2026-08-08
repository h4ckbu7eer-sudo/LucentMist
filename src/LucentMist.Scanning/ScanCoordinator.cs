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
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });
    }

    /// <summary>仅供 ScanWorker 读取队列。</summary>
    public ChannelReader<ScanJob> Reader => _channel.Reader;

    public async Task<string> StartAsync(
        string target,
        string scanType = "ping",
        string ports = "",
        CancellationToken ct = default)
    {
        var rec = await _store.CreateAsync(target, scanType, ports);
        await _channel.Writer.WriteAsync(new ScanJob(rec.Id, target, scanType, ports), ct);
        return rec.Id;
    }
}
