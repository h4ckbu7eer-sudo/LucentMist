namespace LucentMist.Core.Models;

/// <summary>
/// 网络设备
/// </summary>
public record Device
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string IpAddress { get; init; } = string.Empty;
    public string? MacAddress { get; init; }
    public string? Hostname { get; init; }
    public string? Vendor { get; init; }
    public string DeviceType { get; init; } = "unknown";
    public DateTime FirstSeen { get; init; } = DateTime.UtcNow;
    public DateTime LastSeen { get; init; } = DateTime.UtcNow;
    public bool IsActive { get; init; } = true;
    public string[] Tags { get; init; } = [];

    /// <summary>
    /// 设备类型常量
    /// </summary>
    public static class Types
    {
        public const string Router = "router";
        public const string Laptop = "laptop";
        public const string Phone = "phone";
        public const string Iot = "iot";
        public const string Server = "server";
        public const string Unknown = "unknown";
    }
}
