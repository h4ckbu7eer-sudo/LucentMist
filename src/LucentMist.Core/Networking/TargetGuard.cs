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
        CancellationToken ct = default) =>
        await ValidateAsync(
            target,
            Environment.GetEnvironmentVariable("LMIST_ALLOWED_TARGETS"),
            ct);

    /// <summary>
    /// 校验目标及可选授权范围。allowedTargets 使用逗号或分号分隔，支持精确 IP、
    /// CIDR、精确域名及 *.example.com 形式的域名后缀。
    /// </summary>
    public static async Task<TargetValidationResult> ValidateAsync(
        string target,
        string? allowedTargets,
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
            return ValidateCidr(target, allowedTargets);

        if (IPAddress.TryParse(target, out var address))
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                return TargetValidationResult.Reject("IPV6_NOT_SUPPORTED", "当前仅支持 IPv4 扫描目标", "ipv6");
            var result = IsForbiddenIp(address)
                ? TargetValidationResult.Reject("FORBIDDEN_ADDRESS", "扫描目标位于受保护或保留地址范围", "ipv4")
                : TargetValidationResult.Allow("ipv4", [address]);
            return ApplyAuthorizationPolicy(target, result, allowedTargets);
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
            return ApplyAuthorizationPolicy(
                target,
                TargetValidationResult.Allow("hostname", ipv4),
                allowedTargets);
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

    private static TargetValidationResult ValidateCidr(string target, string? allowedTargets)
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

        return ApplyAuthorizationPolicy(
            target,
            TargetValidationResult.Allow("cidr", [ip]),
            allowedTargets);
    }

    private static TargetValidationResult ApplyAuthorizationPolicy(
        string target,
        TargetValidationResult result,
        string? allowedTargets)
    {
        var requiresAuthorization = IsPublicTarget(target, result);
        List<AllowedTargetRule>? rules = null;
        if (!string.IsNullOrWhiteSpace(allowedTargets) &&
            !TryParseAllowedTargets(allowedTargets, out rules))
        {
            return TargetValidationResult.Reject(
                "INVALID_ALLOWED_TARGETS",
                "LMIST_ALLOWED_TARGETS 包含无效条目；已拒绝扫描以避免越权",
                result.TargetType,
                result.ResolvedAddresses);
        }

        // RFC1918 and loopback targets are the normal self-use scope. The explicit
        // allow-list gates public targets without making local networks unusable.
        if (!requiresAuthorization)
        {
            return result with
            {
                RequiresPublicAuthorization = false,
                IsExplicitlyAllowed = false,
            };
        }

        if (string.IsNullOrWhiteSpace(allowedTargets))
            return result with { RequiresPublicAuthorization = requiresAuthorization };

        if (!IsCoveredByRules(target, result, rules!))
        {
            return TargetValidationResult.Reject(
                "TARGET_OUTSIDE_ALLOWED_SCOPE",
                "扫描目标不在 LMIST_ALLOWED_TARGETS 授权范围内",
                result.TargetType,
                result.ResolvedAddresses);
        }

        return result with
        {
            RequiresPublicAuthorization = false,
            IsExplicitlyAllowed = true,
        };
    }

    private static bool IsPublicTarget(string target, TargetValidationResult result)
    {
        if (result.TargetType == "cidr" && TryParseCidr(target, out var range))
            return !PrivateRanges.Any(privateRange => Contains(privateRange, range));

        return result.ResolvedAddresses.Any(address => !IsPrivateOrLoopback(address));
    }

    private static bool IsPrivateOrLoopback(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var value = ToUInt32(address);
        return value >= ToUInt32(127, 0, 0, 0) && value <= ToUInt32(127, 255, 255, 255)
            || value >= ToUInt32(10, 0, 0, 0) && value <= ToUInt32(10, 255, 255, 255)
            || value >= ToUInt32(172, 16, 0, 0) && value <= ToUInt32(172, 31, 255, 255)
            || value >= ToUInt32(192, 168, 0, 0) && value <= ToUInt32(192, 168, 255, 255);
    }

    private static readonly IpRange[] PrivateRanges =
    [
        new(ToUInt32(127, 0, 0, 0), ToUInt32(127, 255, 255, 255)),
        new(ToUInt32(10, 0, 0, 0), ToUInt32(10, 255, 255, 255)),
        new(ToUInt32(172, 16, 0, 0), ToUInt32(172, 31, 255, 255)),
        new(ToUInt32(192, 168, 0, 0), ToUInt32(192, 168, 255, 255)),
    ];

    private static bool TryParseAllowedTargets(string value, out List<AllowedTargetRule> rules)
    {
        rules = [];
        foreach (var raw in value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPAddress.TryParse(raw, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var number = ToUInt32(ip);
                rules.Add(new AllowedTargetRule(null, new IpRange(number, number), false));
                continue;
            }

            if (TryParseCidr(raw, out var range))
            {
                rules.Add(new AllowedTargetRule(null, range, false));
                continue;
            }

            var wildcard = raw.StartsWith("*.", StringComparison.Ordinal);
            var hostname = wildcard ? raw[2..] : raw;
            if (!IsValidHostname(hostname))
                return false;

            rules.Add(new AllowedTargetRule(hostname.ToLowerInvariant(), null, wildcard));
        }

        return rules.Count > 0;
    }

    private static bool IsCoveredByRules(
        string target,
        TargetValidationResult result,
        IReadOnlyList<AllowedTargetRule> rules)
    {
        if (result.TargetType == "hostname")
        {
            var normalized = target.TrimEnd('.').ToLowerInvariant();
            if (rules.Any(rule => rule.Hostname != null &&
                    (rule.Wildcard
                        ? normalized.EndsWith('.' + rule.Hostname, StringComparison.OrdinalIgnoreCase)
                        : normalized.Equals(rule.Hostname, StringComparison.OrdinalIgnoreCase))))
            {
                return true;
            }
        }

        if (result.TargetType == "cidr")
        {
            return TryParseCidr(target, out var targetRange)
                && rules.Any(rule => rule.Range is { } allowed && Contains(allowed, targetRange));
        }

        return result.ResolvedAddresses.Count > 0
            && result.ResolvedAddresses.All(address =>
                rules.Any(rule => rule.Range is { } allowed
                    && Contains(allowed, new IpRange(ToUInt32(address), ToUInt32(address)))));
    }

    private static bool TryParseCidr(string value, out IpRange range)
    {
        range = default;
        var slash = value.IndexOf('/');
        if (slash <= 0 || value.IndexOf('/', slash + 1) >= 0
            || !IPAddress.TryParse(value[..slash], out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(value[(slash + 1)..], out var prefix)
            || prefix is < 0 or > 32)
        {
            return false;
        }

        var number = ToUInt32(ip);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        range = new IpRange(number & mask, (number & mask) | ~mask);
        return true;
    }

    private static bool Contains(IpRange container, IpRange value) =>
        container.Start <= value.Start && container.End >= value.End;

    private readonly record struct IpRange(uint Start, uint End);

    private readonly record struct AllowedTargetRule(
        string? Hostname,
        IpRange? Range,
        bool Wildcard);

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
    public bool RequiresPublicAuthorization { get; init; }

    public bool IsExplicitlyAllowed { get; init; }

    public static TargetValidationResult Allow(string targetType, IReadOnlyList<IPAddress> addresses) =>
        new(true, "OK", "", targetType, addresses);

    public static TargetValidationResult Reject(
        string code,
        string message,
        string targetType = "unknown",
        IReadOnlyList<IPAddress>? addresses = null) =>
        new(false, code, message, targetType, addresses ?? Array.Empty<IPAddress>());
}
