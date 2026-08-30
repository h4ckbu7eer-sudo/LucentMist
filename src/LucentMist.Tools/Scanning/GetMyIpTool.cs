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
        "读取本机 IPv4；主接口优先选择有网关的物理网卡，虚拟网卡单独标注。询问‘我的 IP’时只回答 primaryIp/primaryInterface，不要扫描";

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

        var primary = LocalNetworkInfo.GetPrimaryInterface(entries);
        var interfaces = entries.Select(entry => new
        {
            name = entry.Name,
            ip = entry.Ip,
            prefix = entry.Prefix,
            actualSubnet = ToNetworkCidr(entry.Ip, entry.Prefix),
            suggestedSubnet = ToNetworkCidr(entry.Ip, 24),
            gateway = entry.Gateway,
            isVirtual = entry.IsVirtual,
            isPrimary = entry == primary,
            interfaceType = entry.InterfaceType.ToString(),
        }).ToList();
        var result = new
        {
            primaryIp = primary?.Ip,
            primaryInterface = primary?.Name,
            gateway = primary?.Gateway,
            suggestedSubnet = primary == null ? null : ToNetworkCidr(primary.Ip, 24),
            virtualInterfaceCount = entries.Where(entry => entry.IsVirtual)
                .Select(entry => entry.Name).Distinct(StringComparer.Ordinal).Count(),
            interfaces,
            note = primary == null
                ? "未检测到可用物理主接口；虚拟网卡仅供参考，请明确选择目标，不自动推断主网络"
                : "主接口优先有默认网关的物理网卡；这不是公网出口 IP 或按目标查询的路由。简单 IP 问题仅回答主接口/IP；需要扫描时建议先用 /24 并确认授权",
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

}
