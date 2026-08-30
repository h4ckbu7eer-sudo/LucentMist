using System.Diagnostics;
using System.Net;
using System.Text.Json;
using LucentMist.Core.Networking;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// Reads local interface information without contacting an external IP service.
/// </summary>
public sealed class GetMyIpTool : ITool
{
    private readonly Func<List<LocalNetworkEntry>> _getEntries;

    public GetMyIpTool(Func<List<LocalNetworkEntry>>? getEntries = null)
    {
        _getEntries = getEntries ?? LocalNetworkInfo.GetEntries;
    }

    public string Name => "get_my_ip";

    public string Description =>
        "读取本机活动网卡的 IPv4 地址并推断建议扫描的 /24 子网；当用户说‘我的 IP’、‘本机’或‘我所在的子网’时使用";

    public ToolParameter[] Parameters => [];

    public Task<ToolResult> ExecuteAsync(
        ToolArguments args,
        CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        cancellationToken.ThrowIfCancellationRequested();

        var entries = _getEntries();
        if (entries.Count == 0)
            return Task.FromResult(ToolResult.Fail("未检测到可用的非回环 IPv4 网卡", sw.Elapsed));

        var interfaces = entries.Select(entry => new
        {
            name = entry.Name,
            ip = entry.Ip,
            prefix = entry.Prefix,
            actualSubnet = ToNetworkCidr(entry.Ip, entry.Prefix),
            suggestedSubnet = ToNetworkCidr(entry.Ip, 24),
            gateway = entry.Gateway,
        }).ToList();
        var primary = interfaces.FirstOrDefault(item => IsPrivate(item.ip)) ?? interfaces[0];
        var result = new
        {
            primaryIp = primary.ip,
            suggestedSubnet = primary.suggestedSubnet,
            interfaces,
            note = "建议先扫描 /24 以控制范围；扩大范围前请确认网络边界和授权",
        };

        return Task.FromResult(ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed));
    }

    internal static string ToNetworkCidr(string ip, int prefix)
    {
        if (!IPAddress.TryParse(ip, out var address) || address.GetAddressBytes().Length != 4)
            throw new ArgumentException("必须提供 IPv4 地址", nameof(ip));
        if (prefix is < 0 or > 32)
            throw new ArgumentOutOfRangeException(nameof(prefix));

        var bytes = address.GetAddressBytes();
        var value = ((uint)bytes[0] << 24) |
                    ((uint)bytes[1] << 16) |
                    ((uint)bytes[2] << 8) |
                    bytes[3];
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = value & mask;
        return $"{(network >> 24) & 0xff}.{(network >> 16) & 0xff}.{(network >> 8) & 0xff}.{network & 0xff}/{prefix}";
    }

    private static bool IsPrivate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;
        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
               (bytes[0] == 10 ||
                bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
                bytes[0] == 192 && bytes[1] == 168);
    }
}
