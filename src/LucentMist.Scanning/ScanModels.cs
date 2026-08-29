namespace LucentMist.Scanning;

/// <summary>入队后的扫描任务。</summary>
public record ScanJob(
    string TaskId,
    string Target,
    string ScanType,
    string Ports,
    string Initiator = "unknown");

/// <summary>SQLite 中的扫描任务记录。</summary>
public record ScanTaskRecord
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Target { get; init; } = "";
    public string ScanType { get; init; } = "ping";
    public string Ports { get; init; } = "";
    public string Status { get; set; } = "pending"; // pending / running / completed / failed
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime? StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public int TotalDevices { get; set; }
    public string? ResultJson { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>扫描进度事件，供 SignalR 或日志通道发布。</summary>
public record ScanProgressEvent(
    string TaskId,
    string Status,
    string Message,
    int Percent,
    string? ResultJson = null);

public sealed record ScanAuditRecord
{
    public long Id { get; init; }
    public string EventId { get; init; } = "";
    public string? ScanTaskId { get; init; }
    public DateTime OccurredAt { get; init; }
    public string Target { get; init; } = "";
    public string Initiator { get; init; } = "unknown";
    public string ScanType { get; init; } = "unknown";
    public string Status { get; init; } = "unknown";
    public string Summary { get; init; } = "";
}
