namespace LucentMist.Core.Models;

/// <summary>
/// 网络服务
/// </summary>
public record Service
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string DeviceId { get; init; } = string.Empty;
    public int Port { get; init; }
    public string Protocol { get; init; } = "tcp";
    public string ServiceName { get; init; } = "unknown";
    public string? Banner { get; init; }
    public string? Version { get; init; }
    public string? SslInfo { get; init; }
    public DateTime FirstSeen { get; init; } = DateTime.UtcNow;
    public DateTime LastSeen { get; init; } = DateTime.UtcNow;
}
