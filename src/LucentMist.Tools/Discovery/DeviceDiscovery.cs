using System.Net;
using System.Text.Json.Serialization;

namespace LucentMist.Tools.Discovery;

public static class DeviceDiscovery
{
    private static readonly Lazy<OuiDatabase> Oui = new(() => new OuiDatabase());

    public static async Task<DeviceIdentity> EnrichAsync(string target, CancellationToken ct = default)
    {
        var neighbors = await NeighborTable.ReadAsync([target], ct);
        neighbors.TryGetValue(target, out var mac);
        var mdns = IsPrivateAddress(target) ? await MdnsProbe.ProbeAsync(target, ct) : null;
        return new DeviceIdentity(
            target,
            mac,
            Oui.Value.Lookup(mac) ?? "未知",
            mdns?.Name ?? "未知（未获得有效名称响应）",
            mdns?.Model ?? "未知（需服务指纹或管理接口确认）")
        {
            MdnsStatus = mdns?.Status ?? "not_probed",
            IdentityEvidence = "厂商来自离线 OUI，名称/型号来自未经认证的定向 mDNS 响应（可能为代理公告），均需管理端确认。无响应不代表未广播。邻居表无 DHCP Option，未采集 DHCP。",
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
    [JsonPropertyName("identityEvidence")]
    public string? IdentityEvidence { get; init; }
}
