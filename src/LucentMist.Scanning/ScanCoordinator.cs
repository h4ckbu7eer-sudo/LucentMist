using System.Threading.Channels;
using LucentMist.Core.Networking;
using LucentMist.Tools.Common;

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
        scanType = (scanType ?? "ping").Trim().ToLowerInvariant();
        if (scanType is not ("ping" or "tcp" or "udp"))
            throw new InvalidScanParametersException(
                "INVALID_SCAN_TYPE",
                "scanType 必须是 ping、tcp 或 udp");

        var validation = await TargetGuard.ValidateAsync(target, ct);
        if (!validation.IsAllowed)
            throw new InvalidScanTargetException(validation.Code, validation.Message);

        ports = ports?.Trim() ?? "";
        if (scanType == "ping")
        {
            ports = "";
        }
        else if (!string.IsNullOrEmpty(ports) && !PortHelper.TryParsePorts(ports, out _))
        {
            throw new InvalidScanParametersException(
                "INVALID_PORTS",
                "ports 必须是 1-65535 的数字、逗号列表或正向范围");
        }

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

public abstract class InvalidScanRequestException : Exception
{
    protected InvalidScanRequestException(string code, string message) : base(message) =>
        Code = code;

    public string Code { get; }
}

public sealed class InvalidScanTargetException : InvalidScanRequestException
{
    public InvalidScanTargetException(string code, string message) : base(code, message) { }
}

public sealed class InvalidScanParametersException : InvalidScanRequestException
{
    public InvalidScanParametersException(string code, string message) : base(code, message) { }
}
