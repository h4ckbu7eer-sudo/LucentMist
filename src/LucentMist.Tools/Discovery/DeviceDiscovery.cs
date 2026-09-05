using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using LucentMist.Tools.Security;
using Microsoft.Win32;

namespace LucentMist.Tools.Discovery;

public static class DeviceDiscovery
{
    private static readonly Lazy<OuiDatabase> Oui = new(() => new OuiDatabase());

    public static async Task<DeviceIdentity> EnrichAsync(string target, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (IPAddress.TryParse(target, out var address) && IPAddress.IsLoopback(address))
            return BuildLoopbackIdentity(target, ReadLocalHardwareIdentity());
        if (address != null && TryGetLocalInterface(address, out var localNic, out var localMac))
        {
            var nic = localNic!;
            var nicVendor = Oui.Value.Lookup(localMac);
            var hardware = ReadLocalHardwareIdentity();
            return new DeviceIdentity(
                target,
                localMac,
                hardware.Manufacturer ?? (nicVendor == null
                    ? localMac == null ? "未知（本机接口没有可用 MAC）" : "未知（OUI 库无此前缀）"
                    : $"未知（网卡厂商：{nicVendor}）"),
                Environment.MachineName,
                hardware.Model ?? $"未知（网卡：{nic.Description}；整机型号未读取）")
            {
                MdnsStatus = "not_applicable_local_interface",
                IdentityEvidence = "目标 IP 与本机启用的 IPv4 接口精确匹配；名称来自操作系统，MAC 来自该接口。" +
                    (hardware.Model != null
                        ? "厂商/型号来自本机 DMI/BIOS 清单；"
                        : "整机 DMI/BIOS 未提供可用厂商型号；") +
                    $"网卡描述为 {nic.Description}，网卡 OUI 厂商为 {nicVendor ?? "未知"}。网卡厂商不冒充整机厂商。",
            };
        }
        var neighbors = await NeighborTable.ReadAsync([target], ct);
        neighbors.TryGetValue(target, out var mac);
        return await EnrichRemoteAsync(target, mac, ct);
    }

    internal static async Task<DeviceIdentity> EnrichRemoteAsync(string target, string? mac, CancellationToken ct)
    {
        var isPrivate = IsPrivateAddress(target);
        var mdnsTask = isPrivate ? MdnsProbe.ProbeAsync(target, ct) : null;
        var upnpTask = isPrivate ? UpnpProbe.ProbeAsync(target, ct) : null;
        if (mdnsTask != null && upnpTask != null) await Task.WhenAll(mdnsTask, upnpTask);
        var mdns = mdnsTask == null ? null : await mdnsTask;
        var upnp = upnpTask == null ? null : await upnpTask;
        if (!isPrivate && string.IsNullOrWhiteSpace(mac))
            return BuildPublicIdentityWithoutLayer2Evidence(target);
        return new DeviceIdentity(
            target,
            mac,
            upnp?.Manufacturer ?? Oui.Value.Lookup(mac) ?? (mac == null ? "未知（邻居表无 MAC，无法查询 OUI）" : "未知（OUI 库无此前缀）"),
            mdns?.Name ?? upnp?.Name ?? "未知（未获得有效名称响应）",
            mdns?.Model ?? upnp?.Model ?? "未知（本次 mDNS/UPnP 未取得型号，需管理端确认）")
        {
            MdnsStatus = mdns?.Status ?? "not_probed",
            UpnpStatus = upnp?.Status ?? "not_probed",
            IdentityEvidence = "厂商来自 UPnP 设备声明或离线 OUI；名称/型号来自未经认证的定向 mDNS/UPnP 响应，均需管理端确认。无响应不代表未广播，不用厂商或主机名猜型号。邻居表无 DHCP Option，未采集 DHCP。",
        };
    }

    internal static DeviceIdentity BuildLoopbackIdentity(string target, (string? Manufacturer, string? Model) hardware) =>
        new(target, null, hardware.Manufacturer ?? "未知（本机 BIOS/DMI 未提供厂商）",
            Environment.MachineName, hardware.Model ?? "未知（本机 BIOS/DMI 未提供型号）")
        {
            MdnsStatus = "not_applicable",
            IdentityEvidence = "本机名称来自操作系统；整机厂商/型号来自本机 BIOS/DMI。回环地址无物理 MAC，不用 OUI 推断整机厂商。",
        };

    internal static DeviceIdentity BuildPublicIdentityWithoutLayer2Evidence(string target) => new(
        target,
        null,
        "未知（公网 IP 无二层 MAC/OUI 证据）",
        "未知（公网目标未执行局域网 mDNS）",
        "未知（服务 Banner 未提供硬件型号）")
    {
        MdnsStatus = "not_applicable_public_target",
        IdentityEvidence = "公网路由不会传递目标网卡 MAC，mDNS 也不跨公网；" +
            "SSH/HTTP 服务版本不能可靠推出硬件厂商或型号。未使用归属运营商冒充设备厂商。",
    };

    internal static async Task<DeviceIdentity> EnrichServicesAsync(DeviceIdentity device, IEnumerable<int> openPorts, CancellationToken ct)
    {
        // Probe only an already-discovered web port, with a small total budget, no redirects/authentication.
        var port = openPorts.Where(HttpBannerProbe.IsHttpPort).OrderBy(p => p is 80 or 8080 ? 0 : 1).FirstOrDefault();
        if (port == 0) return device;
        var http = await HttpBannerProbe.ProbeDetailedAsync(device.Ip, port, 2000, ct);
        var page = http.PageIdentity;
        return page == null ? device : device with
        {
            Name = device.Name.StartsWith("未知", StringComparison.Ordinal) && page.Title != null ? $"网页：{page.Title}" : device.Name,
            Vendor = device.Vendor.StartsWith("未知", StringComparison.Ordinal) ? page.Vendor ?? device.Vendor : device.Vendor,
            Model = device.Model.StartsWith("未知", StringComparison.Ordinal) || device.Model.StartsWith("未公开", StringComparison.Ordinal) ? page.Model ?? device.Model : device.Model,
            PageIdentity = page,
            IdentityEvidence = device.IdentityEvidence + " " + page.Evidence,
        };
    }

    private static bool IsPrivateAddress(string value)
    {
        if (!IPAddress.TryParse(value, out var address)) return false;
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
               (bytes[0] == 10 || bytes[0] == 127 ||
                bytes[0] == 192 && bytes[1] == 168 ||
                bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                bytes[0] == 169 && bytes[1] == 254);
    }

    internal static bool TryGetLocalInterface(
        IPAddress address,
        out NetworkInterface? networkInterface,
        out string? mac)
    {
        networkInterface = null;
        mac = null;
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        try
        {
            networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                .FirstOrDefault(nic => nic.GetIPProperties().UnicastAddresses.Any(item =>
                    item.Address.AddressFamily == AddressFamily.InterNetwork && item.Address.Equals(address)));
            if (networkInterface == null) return false;
            var bytes = networkInterface.GetPhysicalAddress().GetAddressBytes();
            mac = bytes.Length >= 6
                ? string.Join(":", bytes.Select(value => value.ToString("X2")))
                : null;
            return true;
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    internal static (string? Manufacturer, string? Model) ReadLocalHardwareIdentity()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS", writable: false);
                return CleanHardwareIdentity(
                    key?.GetValue("SystemManufacturer") as string,
                    key?.GetValue("SystemProductName") as string);
            }
            if (OperatingSystem.IsLinux())
            {
                var manufacturerPath = "/sys/class/dmi/id/sys_vendor";
                var modelPath = "/sys/class/dmi/id/product_name";
                return CleanHardwareIdentity(
                    File.Exists(manufacturerPath) ? File.ReadAllText(manufacturerPath) : null,
                    File.Exists(modelPath) ? File.ReadAllText(modelPath) : null);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Hardware inventory is optional evidence; keep the boundary honest.
        }
        return (null, null);
    }

    internal static (string? Manufacturer, string? Model) CleanHardwareIdentity(string? manufacturer, string? model)
    {
        static string? Clean(string? value)
        {
            var text = value?.Trim();
            return string.IsNullOrWhiteSpace(text) ||
                   text.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) ||
                   text.Equals("System Product Name", StringComparison.OrdinalIgnoreCase) ||
                   text.Equals("Not Applicable", StringComparison.OrdinalIgnoreCase) ||
                   text.Equals("Default string", StringComparison.OrdinalIgnoreCase)
                ? null
                : text;
        }
        return (Clean(manufacturer), Clean(model));
    }
}

public sealed record DeviceIdentity(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("mac")] string? Mac,
    [property: JsonPropertyName("vendor")] string Vendor,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("model")] string Model)
{
    [JsonPropertyName("mdnsStatus")]
    public string MdnsStatus { get; init; } = "not_probed";
    [JsonPropertyName("upnpStatus")]
    public string UpnpStatus { get; init; } = "not_probed";
    [JsonPropertyName("identityEvidence")]
    public string? IdentityEvidence { get; init; }
    [JsonPropertyName("pageIdentity")]
    public HttpPageIdentity? PageIdentity { get; init; }
}
