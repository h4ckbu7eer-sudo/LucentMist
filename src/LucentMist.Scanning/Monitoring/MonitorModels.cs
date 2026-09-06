using System.Net;
using System.Text.RegularExpressions;
using LucentMist.Tools.Common;

namespace LucentMist.Scanning.Monitoring;

public sealed record MonitorScope(string Subnet, string Ports)
{
    // Device identity, trust and alerts belong to a network, not a scan recipe.
    public string Id => Subnet;
    public static MonitorScope Create(string subnet, string ports)
    {
        var parts = subnet.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.GetAddressBytes().Length != 4 ||
            !int.TryParse(parts.Length == 1 ? "32" : parts[1], out var prefix) || prefix is < 24 or > 32)
            throw new ArgumentException("家庭监控只接受 IPv4 /24～/32 网段或单个 IP，每轮最多 256 个地址。");
        var bytes = ip.GetAddressBytes();
        if (!(bytes[0] is 10 or 127 || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31))
            throw new ArgumentException("家庭监控仅支持私有/回环网段，不自动扫描公网。");
        if (!PortHelper.TryParsePorts(ports, out var parsed) || parsed.Count > 64)
            throw new ArgumentException("监控端口需为有效端口列表/范围，最多 64 个。");
        var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        var network = value & (uint.MaxValue << (32 - prefix));
        return new($"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefix}",
            string.Join(',', parsed.Distinct().Order()));
    }
}

public sealed record MonitorDevice(string Ip, string? Mac, string Vendor, string Name,
    int[]? OpenPorts, Dictionary<int, string>? Services = null, string[]? Vulnerabilities = null, string[]? Warnings = null,
    string? Model = null, string[]? MdnsServices = null)
{
    public static string? NormalizeMac(string? value)
    {
        var compact = value?.Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
        if (compact == null || !Regex.IsMatch(compact, "^[0-9A-F]{12}$") || compact is "000000000000" or "FFFFFFFFFFFF") return null;
        if ((Convert.ToByte(compact[..2], 16) & 1) != 0) return null;
        return string.Join(':', Enumerable.Range(0, 6).Select(i => compact.Substring(i * 2, 2)));
    }
    public string Id => NormalizeMac(Mac) is { } mac ? "mac:" + mac : "ip:" + Ip;
}
public sealed record NetworkSnapshot(bool DiscoverySucceeded, MonitorDevice[] Devices, string? Error = null);
public sealed record MonitorPortObservation(bool Open, DateTimeOffset At);
public sealed record MonitorIdentityAssociation(string Status, string[] RelatedDeviceIds, string Evidence);
public sealed record KnownDevice(MonitorDevice Device, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, bool Present,
    bool Trusted = false, DateTimeOffset? PortsObservedAt = null, bool LastPortScanSucceeded = false, bool IdentityConfirmed = true,
    Dictionary<int, MonitorPortObservation>? PortHistory = null, string? LastPortScope = null,
    MonitorIdentityAssociation? Association = null);
public sealed record MonitorAlert(long Id, DateTimeOffset At, string Kind, string Priority, string Ip, string Message);
public sealed record MonitorUpdate(bool BaselineCreated, bool Applied, KnownDevice[] Devices, MonitorAlert[] Alerts, string Summary);
