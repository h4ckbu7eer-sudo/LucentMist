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
        var name = IsPrivateAddress(target) ? await MdnsProbe.ResolveNameAsync(target, ct) : null;
        return new DeviceIdentity(
            target,
            mac,
            Oui.Value.Lookup(mac) ?? "未知",
            name ?? "未广播",
            "未知（需服务指纹或管理接口确认）");
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
    [property: JsonPropertyName("model")] string Model);
