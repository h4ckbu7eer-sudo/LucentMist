using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LucentMist.Core.Networking;

public record LocalNetworkEntry(string Name, string Ip, int Prefix, string Gateway)
{
    public string Description { get; init; } = string.Empty;
    public NetworkInterfaceType InterfaceType { get; init; } = NetworkInterfaceType.Unknown;
    public bool IsVirtualDevice { get; init; }
    public bool IsVirtual => LocalNetworkInfo.IsVirtualInterface(this);
}

/// <summary>
/// 本机网卡信息，供 API/CLI 注入到 Agent 提示词，避免 LLM 猜测错误网段。
/// </summary>
public static class LocalNetworkInfo
{
    public static List<LocalNetworkEntry> GetEntries()
    {
        var results = new List<LocalNetworkEntry>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;

            try
            {
                var props = nic.GetIPProperties();
                var gateway = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(IsUsableIpv4)?.ToString() ?? "未知";
                foreach (var ipv4 in props.UnicastAddresses.Where(a => IsUsableIpv4(a.Address)))
                {
                    var mask = ipv4.IPv4Mask?.ToString();
                    var prefix = mask != null ? MaskToPrefix(mask) : 24;
                    results.Add(new LocalNetworkEntry(nic.Name, ipv4.Address.ToString(), prefix, gateway)
                    {
                        Description = nic.Description,
                        InterfaceType = nic.NetworkInterfaceType,
                        IsVirtualDevice = IsLinuxVirtualDevice(nic.Name),
                    });
                }
            }
            catch (NetworkInformationException)
            {
                // A disappearing adapter must not hide the remaining interfaces.
            }
        }

        return results;
    }

    /// <summary>
    /// Shared by the tool and prompt injection. Stable tie-breaking avoids dependence
    /// on OS enumeration order; this is not a destination-specific route lookup.
    /// </summary>
    public static LocalNetworkEntry? GetPrimaryInterface(IEnumerable<LocalNetworkEntry>? entries = null) =>
        (entries ?? GetEntries())
            .Where(entry => !entry.IsVirtual && IsPhysicalType(entry.InterfaceType) &&
                            IPAddress.TryParse(entry.Ip, out var ip) && IsUsableIpv4(ip))
            .Where(entry => HasGateway(entry) || IsPrivate(entry.Ip))
            .OrderByDescending(HasGateway)
            .ThenByDescending(entry => IsPrivate(entry.Ip))
            .ThenBy(entry => entry.Name, StringComparer.Ordinal)
            .ThenBy(entry => entry.Ip, StringComparer.Ordinal)
            .FirstOrDefault();

    public static string InjectLocalNetworkInfo(string message, IEnumerable<LocalNetworkEntry>? entries = null)
    {
        var snapshot = (entries ?? GetEntries()).ToList();
        var primary = GetPrimaryInterface(snapshot);
        var virtualCount = snapshot.Where(entry => entry.IsVirtual)
            .Select(entry => entry.Name).Distinct(StringComparer.Ordinal).Count();
        var primaryInfo = primary == null
            ? "未检测到可用物理主接口，不得把虚拟网卡当作主接口或自行选择扫描子网"
            : $"主接口: {primary.Name}；主 IPv4: {primary.Ip}/{primary.Prefix}；网关: {primary.Gateway}";
        return $"[本机网络信息: {primaryInfo}；另有 {virtualCount} 个虚拟网卡（非主接口）。" +
               "简单询问本机 IP 时仅回答主接口/IP，可附虚拟网卡数量，不并列罗列所有接口。" +
               "若 get_my_ip 的最新结果与此启动快照不同，以工具的 primaryIp 为准并说明网络可能变化。] " + message;
    }

    public static bool IsVirtualInterface(LocalNetworkEntry entry)
    {
        if (entry.IsVirtualDevice || entry.InterfaceType is NetworkInterfaceType.Loopback or
            NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
            return true;

        var identity = entry.Name + " " + entry.Description;
        if (new[] { "vmnet", "vethernet", "vmware", "virtual", "loopback", "tunnel", "pseudo", "hyper-v", "wsl" }
            .Any(marker => identity.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            return true;

        var name = entry.Name.ToLowerInvariant();
        return name == "lo" || new[] { "docker", "veth", "virbr", "br-", "tun", "tap", "wg", "tailscale", "zt" }
            .Any(prefix => name.StartsWith(prefix, StringComparison.Ordinal));
    }

    private static bool IsPhysicalType(NetworkInterfaceType type) => type is
        NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211 or
        NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT or
        NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.Unknown;

    private static bool HasGateway(LocalNetworkEntry entry) =>
        IPAddress.TryParse(entry.Gateway, out var gateway) && IsUsableIpv4(gateway);

    private static bool IsUsableIpv4(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(ip)) return false;
        var bytes = ip.GetAddressBytes();
        return bytes[0] is > 0 and < 224 && !(bytes[0] == 169 && bytes[1] == 254);
    }

    private static bool IsPrivate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
               bytes[0] == 192 && bytes[1] == 168;
    }

    private static bool IsLinuxVirtualDevice(string name)
    {
        if (!OperatingSystem.IsLinux()) return false;
        try
        {
            var resolved = new DirectoryInfo(Path.Combine("/sys/class/net", name)).ResolveLinkTarget(true);
            return resolved?.FullName.Contains("/devices/virtual/net/", StringComparison.Ordinal) == true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static int MaskToPrefix(string mask)
    {
        try
        {
            var parts = mask.Split('.').Select(int.Parse).ToArray();
            uint bits = 0;
            foreach (var p in parts) bits = (bits << 8) | (uint)p;
            var prefix = 0;
            while (bits > 0)
            {
                if ((bits & 0x80000000) != 0) prefix++;
                bits <<= 1;
            }
            return prefix;
        }
        catch
        {
            return 24;
        }
    }
}
