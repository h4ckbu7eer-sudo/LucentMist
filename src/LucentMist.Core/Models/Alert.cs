namespace LucentMist.Core.Models;

/// <summary>
/// 网络告警
/// </summary>
public record Alert
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string? DeviceId { get; init; }
    public string AlertType { get; init; } = "info";
    public string Severity { get; init; } = "info";
    public string Title { get; init; } = string.Empty;
    public string? Description { get; init; }
    public bool IsRead { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    public static class Types
    {
        public const string NewDevice = "new_device";
        public const string Offline = "offline";
        public const string PortChange = "port_change";
        public const string Security = "security";
    }

    public static class Severities
    {
        public const string Info = "info";
        public const string Warning = "warning";
        public const string Critical = "critical";
    }
}
