namespace LucentMist.Core.Models;

/// <summary>
/// 扫描结果
/// </summary>
public record ScanResult
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string TaskId { get; init; } = string.Empty;
    public string IpAddress { get; init; } = string.Empty;
    public bool IsAlive { get; init; }
    public double? LatencyMs { get; init; }
    public int[] OpenPorts { get; init; } = [];
    public string? RawData { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}
