using System.Net;
using System.Net.Sockets;

namespace LucentMist.Core.Networking;

/// <summary>
/// 扫描目标的统一安全策略。允许本机、私有地址和公网地址，但拒绝会覆盖
/// 云元数据/链路本地、共享地址空间、组播或保留地址的目标。
/// </summary>
public static class TargetGuard
{
    public static TargetValidationResult ValidateSyntax(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
            return TargetValidationResult.Denied("TARGET_REQUIRED", "必须指定扫描目标");
        if (!string.Equals(target, target.Trim(), StringComparison.Ordinal))
            return TargetValidationResult.Denied("TARGET_WHITESPACE", "扫描目标不能包含首尾空白字符");
        if (target.Length > 253)
            return TargetValidationResult.Denied("TARGET_TOO_LONG", "扫描目标长度不能超过 253 个字符");
        if (target.IndexOfAny(['\0', '\n', '\r']) >= 0)
            return TargetValidationResult.Denied("TARGET_CONTROL_CHARACTER", "扫描目标不能包含控制字符");

        if (target.Contains('/'))
        {
            var slash = target.IndexOf('/');
            if (slash == 0 || target.IndexOf('/', slash + 1) >= 0 ||
                !IPAddress.TryParse(target[..slash], out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork ||
                !int.TryParse(target[(slash + 1)..], out var prefix) ||
                prefix is < 8 or > 32)
            {
                return TargetValidationResult.Denied(
                    "INVALID_CIDR", "CIDR 必须是前缀长度为 8 到 32 的 IPv4 网段");
            }

            return CidrIntersectsForbiddenRange(ip, prefix)
                ? TargetValidationResult.Denied("FORBIDDEN_NETWORK", "CIDR 与保留或受保护的地址范围重叠")
                : TargetValidationResult.Allowed(TargetKind.Cidr);
        }

        if (IPAddress.TryParse(target, out var address))
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                return TargetValidationResult.Denied("IPV6_NOT_SUPPORTED", "当前仅支持 IPv4 扫描目标");
            return IsForbiddenIp(address)
                ? TargetValidationResult.Denied("FORBIDDEN_ADDRESS", "目标属于保留或受保护的地址范围")
                : TargetValidationResult.Allowed(TargetKind.IpAddress, [address.ToString()]);
        }

        return IsValidHostname(target)
            ? TargetValidationResult.Allowed(TargetKind.Hostname)
            : TargetValidationResult.Denied("INVALID_HOSTNAME", "目标必须是合法的 IPv4、CIDR、域名或主机名");
    }

    public static async Task<TargetValidationResult> ValidateAsync(
        string? target, CancellationToken ct = default)
    {
        var syntax = ValidateSyntax(target);
        if (!syntax.IsAllowed || syntax.Kind is not TargetKind.Hostname)
            return syntax;

        try
        {
            var addresses = (await Dns.GetHostAddressesAsync(target!, ct))
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Distinct()
                .ToArray();
            if (addresses.Length == 0)
                return TargetValidationResult.Denied("HOST_NOT_RESOLVED", "主机名没有可用的 IPv4 地址");
            if (addresses.Any(IsForbiddenIp))
                return TargetValidationResult.Denied(
                    "FORBIDDEN_ADDRESS", "主机名解析到了保留或受保护的地址范围");

            return TargetValidationResult.Allowed(
                TargetKind.Hostname, addresses.Select(a => a.ToString()).ToArray());
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            return TargetValidationResult.Denied("HOST_NOT_RESOLVED", "无法解析扫描目标主机名");
        }
    }

    public static async Task<bool> IsAllowedAsync(string target, CancellationToken ct = default) =>
        (await ValidateAsync(target, ct)).IsAllowed;

    public static async Task<string?> ResolveSingleTargetAsync(
        string target, CancellationToken ct = default)
    {
        var result = await ValidateAsync(target, ct);
        return result.IsAllowed && result.Kind is not TargetKind.Cidr
            ? result.ResolvedAddresses.FirstOrDefault()
            : null;
    }

    private static bool CidrIntersectsForbiddenRange(IPAddress address, int prefix)
    {
        var value = ToUInt32(address);
        var mask = prefix == 0 ? 0U : uint.MaxValue << (32 - prefix);
        var start = value & mask;
        var end = start | ~mask;

        return Intersects(start, end, 0x00000000, 0x00FFFFFF) ||       // 0.0.0.0/8
               Intersects(start, end, 0x64400000, 0x647FFFFF) ||       // 100.64.0.0/10
               Intersects(start, end, 0xA9FE0000, 0xA9FEFFFF) ||       // 169.254.0.0/16
               Intersects(start, end, 0xE0000000, 0xFFFFFFFF);         // 224.0.0.0/3
    }

    private static bool Intersects(uint start, uint end, uint forbiddenStart, uint forbiddenEnd) =>
        start <= forbiddenEnd && forbiddenStart <= end;

    private static uint ToUInt32(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static bool IsForbiddenIp(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return true;
        var b = address.GetAddressBytes();
        return b[0] == 0 ||
               b[0] == 169 && b[1] == 254 ||
               b[0] == 100 && b[1] is >= 64 and <= 127 ||
               b[0] >= 224;
    }

    private static bool IsValidHostname(string hostname)
    {
        if (hostname.Length == 0 || hostname.Length > 253 ||
            hostname.StartsWith('.') || hostname.EndsWith('.') || hostname.Contains(".."))
            return false;

        var hasLetter = false;
        foreach (var label in hostname.Split('.'))
        {
            if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[^1] == '-')
                return false;
            foreach (var c in label)
            {
                if (char.IsAsciiLetter(c)) hasLetter = true;
                else if (!char.IsAsciiDigit(c) && c != '-') return false;
            }
        }
        return hasLetter;
    }
}

public enum TargetKind
{
    Unknown,
    IpAddress,
    Cidr,
    Hostname,
}

public sealed record TargetValidationResult(
    bool IsAllowed,
    string Code,
    string Message,
    TargetKind Kind,
    IReadOnlyList<string> ResolvedAddresses)
{
    public static TargetValidationResult Allowed(TargetKind kind, IReadOnlyList<string>? addresses = null) =>
        new(true, "ALLOWED", string.Empty, kind, addresses ?? Array.Empty<string>());

    public static TargetValidationResult Denied(string code, string message) =>
        new(false, code, message, TargetKind.Unknown, Array.Empty<string>());
}
