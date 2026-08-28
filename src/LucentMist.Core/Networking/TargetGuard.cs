using System.Net;
using System.Net.Sockets;

namespace LucentMist.Core.Networking;

/// <summary>
/// 扫描目标安全校验。扫描器仍需支持局域网和本机目标，因此不禁止私有地址；
/// 只拦截云元数据、链路本地、组播和保留地址。
/// </summary>
public static class TargetGuard
{
    private static readonly (uint Start, uint End)[] ForbiddenRanges =
    [
        (ToUInt32(0, 0, 0, 0), ToUInt32(0, 255, 255, 255)),
        (ToUInt32(100, 64, 0, 0), ToUInt32(100, 127, 255, 255)),
        (ToUInt32(169, 254, 0, 0), ToUInt32(169, 254, 255, 255)),
        (ToUInt32(224, 0, 0, 0), ToUInt32(255, 255, 255, 255)),
    ];

    public static async Task<bool> IsAllowedAsync(string target, CancellationToken ct = default) =>
        (await ValidateAsync(target, ct)).IsAllowed;

    public static async Task<TargetValidationResult> ValidateAsync(
        string target,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(target))
            return TargetValidationResult.Reject("EMPTY_TARGET", "必须指定扫描目标");
        if (target.Length > 253)
            return TargetValidationResult.Reject("TARGET_TOO_LONG", "扫描目标长度不能超过 253 个字符");
        if (target.IndexOfAny(['\0', '\n', '\r']) >= 0)
            return TargetValidationResult.Reject("INVALID_TARGET", "扫描目标包含非法控制字符");

        if (target.Contains('/'))
            return ValidateCidr(target);

        if (IPAddress.TryParse(target, out var address))
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                return TargetValidationResult.Reject("IPV6_NOT_SUPPORTED", "当前仅支持 IPv4 扫描目标", "ipv6");
            return IsForbiddenIp(address)
                ? TargetValidationResult.Reject("FORBIDDEN_ADDRESS", "扫描目标位于受保护或保留地址范围", "ipv4")
                : TargetValidationResult.Allow("ipv4", [address]);
        }

        if (!IsValidHostname(target))
            return TargetValidationResult.Reject("INVALID_HOSTNAME", "目标不是合法的主机名", "hostname");

        try
        {
            ct.ThrowIfCancellationRequested();
            var addresses = await Dns.GetHostAddressesAsync(target, ct);
            var ipv4 = addresses
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Distinct()
                .ToArray();
            if (ipv4.Length == 0)
                return TargetValidationResult.Reject("NO_IPV4_ADDRESS", "主机名没有可用的 IPv4 地址", "hostname");
            if (ipv4.Any(IsForbiddenIp))
                return TargetValidationResult.Reject(
                    "FORBIDDEN_ADDRESS",
                    "主机名解析到了受保护或保留地址范围",
                    "hostname",
                    ipv4);
            return TargetValidationResult.Allow("hostname", ipv4);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            return TargetValidationResult.Reject("DNS_RESOLUTION_FAILED", "无法解析扫描目标", "hostname");
        }
        catch (ArgumentException)
        {
            return TargetValidationResult.Reject("DNS_RESOLUTION_FAILED", "无法解析扫描目标", "hostname");
        }
    }

    public static async Task<string?> ResolveSingleTargetAsync(
        string target, CancellationToken ct = default)
    {
        var result = await ValidateAsync(target, ct);
        if (!result.IsAllowed || result.TargetType == "cidr") return null;
        return result.ResolvedAddresses.FirstOrDefault()?.ToString();
    }

    private static TargetValidationResult ValidateCidr(string target)
    {
        var slash = target.IndexOf('/');
        if (slash == 0 || target.IndexOf('/', slash + 1) >= 0 ||
            !IPAddress.TryParse(target[..slash], out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(target[(slash + 1)..], out var prefix) ||
            prefix is < 8 or > 32)
        {
            return TargetValidationResult.Reject(
                "INVALID_CIDR",
                "目标必须是合法的 IPv4 CIDR，前缀范围为 /8 到 /32",
                "cidr");
        }

        var value = ToUInt32(ip);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var start = value & mask;
        var end = start | ~mask;
        if (ForbiddenRanges.Any(range => start <= range.End && end >= range.Start))
        {
            return TargetValidationResult.Reject(
                "FORBIDDEN_ADDRESS_RANGE",
                "CIDR 范围与受保护或保留地址范围重叠",
                "cidr");
        }

        return TargetValidationResult.Allow("cidr", [ip]);
    }

    private static bool IsForbiddenIp(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return true;
        var value = ToUInt32(address);
        return ForbiddenRanges.Any(range => value >= range.Start && value <= range.End);
    }

    private static bool IsValidHostname(string hostname)
    {
        if (hostname.Length == 0 || hostname.Length > 253) return false;
        if (hostname.StartsWith('.') || hostname.EndsWith('.') || hostname.Contains("..")) return false;

        var hasLetter = false;
        foreach (var label in hostname.Split('.'))
        {
            if (label.Length == 0 || label.Length > 63) return false;
            if (label[0] == '-' || label[^1] == '-') return false;

            var labelHasLetter = false;
            foreach (var c in label)
            {
                if (c is >= 'a' and <= 'z' or >= 'A' and <= 'Z')
                {
                    labelHasLetter = true;
                    continue;
                }
                if (c is >= '0' and <= '9') continue;
                return false;
            }
            hasLetter |= labelHasLetter;
        }

        return hasLetter;
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4) return uint.MaxValue;
        return ToUInt32(bytes[0], bytes[1], bytes[2], bytes[3]);
    }

    private static uint ToUInt32(byte a, byte b, byte c, byte d) =>
        ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;
}

public sealed record TargetValidationResult(
    bool IsAllowed,
    string Code,
    string Message,
    string TargetType,
    IReadOnlyList<IPAddress> ResolvedAddresses)
{
    public static TargetValidationResult Allow(string targetType, IReadOnlyList<IPAddress> addresses) =>
        new(true, "OK", "", targetType, addresses);

    public static TargetValidationResult Reject(
        string code,
        string message,
        string targetType = "unknown",
        IReadOnlyList<IPAddress>? addresses = null) =>
        new(false, code, message, targetType, addresses ?? Array.Empty<IPAddress>());
}
