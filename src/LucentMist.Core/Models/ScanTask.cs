namespace LucentMist.Core.Models;

/// <summary>
/// 扫描任务
/// </summary>
public record ScanTask
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Target { get; init; } = string.Empty;
    public string ScanType { get; init; } = "full";
    public string Status { get; init; } = "pending";
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime? StartedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
    public int TotalDevices { get; init; }
    public string? ErrorMessage { get; init; }

    public static class Statuses
    {
        public const string Pending = "pending";
        public const string Running = "running";
        public const string Completed = "completed";
        public const string Failed = "failed";
    }

    public static class Types
    {
        public const string Ping = "ping";
        public const string Port = "port";
        public const string Service = "service";
        public const string Full = "full";
    }
}
