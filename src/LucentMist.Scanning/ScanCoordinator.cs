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
        CancellationToken ct = default,
        ScanRequestContext? context = null)
    {
        var initiator = string.IsNullOrWhiteSpace(context?.Initiator)
            ? "unknown"
            : context.Initiator;
        var auditEventId = Guid.NewGuid().ToString("N");
        scanType = (scanType ?? "ping").Trim().ToLowerInvariant();
        if (scanType is not ("ping" or "tcp" or "udp"))
        {
            await _store.AppendAuditAsync(
                auditEventId, null, target, initiator, scanType, "rejected", "扫描类型无效", ct);
            throw new InvalidScanParametersException(
                "INVALID_SCAN_TYPE",
                "scanType 必须是 ping、tcp 或 udp");
        }

        var validation = await TargetGuard.ValidateAsync(target, ct);
        if (!validation.IsAllowed)
        {
            await _store.AppendAuditAsync(
                auditEventId, null, target, initiator, scanType, "rejected", validation.Code, ct);
            throw new InvalidScanTargetException(validation.Code, validation.Message);
        }
        if (validation.RequiresPublicAuthorization && context?.PublicTargetAuthorized != true)
        {
            await _store.AppendAuditAsync(
                auditEventId,
                null,
                target,
                initiator,
                scanType,
                "rejected",
                "PUBLIC_TARGET_AUTHORIZATION_REQUIRED",
                ct);
            throw new InvalidScanTargetException(
                "PUBLIC_TARGET_AUTHORIZATION_REQUIRED",
                "公网目标需要先确认你拥有扫描授权");
        }

        ports = ports?.Trim() ?? "";
        if (scanType == "ping")
        {
            ports = "";
        }
        else if (!string.IsNullOrEmpty(ports) && !PortHelper.TryParsePorts(ports, out _))
        {
            await _store.AppendAuditAsync(
                auditEventId, null, target, initiator, scanType, "rejected", "INVALID_PORTS", ct);
            throw new InvalidScanParametersException(
                "INVALID_PORTS",
                "ports 必须是 1-65535 的数字、逗号列表或正向范围");
        }

        var rec = await _store.CreateAsync(target, scanType, ports);
        await _store.AppendAuditAsync(
            rec.Id, rec.Id, target, initiator, scanType, "queued", "扫描任务已入队", ct);
        if (!_channel.Writer.TryWrite(new ScanJob(rec.Id, target, scanType, ports, initiator)))
        {
            try { await _store.MarkFailedAsync(rec.Id, "扫描队列已满，请稍后重试"); }
            catch { /* 保留队列已满错误 */ }
            await _store.AppendAuditAsync(
                rec.Id, rec.Id, target, initiator, scanType, "failed", "扫描队列已满", ct);
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
