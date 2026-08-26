using System.Net;
using System.Net.Sockets;

namespace LucentMist.Core.Networking;

/// <summary>
/// 扫描目标安全校验。扫描器仍需支持局域网和本机目标，因此不禁止私有地址；
/// 只拦截云元数据、链路本地、组播和保留地址。
/// </summary>
public static class TargetGuard
{
    public static async Task<bool> IsAllowedAsync(string target, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        if (target.Length > 253) return false;
        if (target.IndexOfAny(['\0', '\n', '\r']) >= 0) return false;

        if (target.Contains('/'))
        {
            var slash = target.IndexOf('/');
            if (slash == 0 || target.IndexOf('/', slash + 1) >= 0) return false;
            if (!IPAddress.TryParse(target[..slash], out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork ||
                !int.TryParse(target[(slash + 1)..], out var prefix) ||
                prefix is < 8 or > 32)
                return false;
            return !IsForbiddenIp(ip);
        }

        if (IPAddress.TryParse(target, out var address))
        {
            return address.AddressFamily == AddressFamily.InterNetwork &&
                   !IsForbiddenIp(address);
        }

        if (!IsValidHostname(target)) return false;

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(target, ct);
            return addresses.Any(a => a.AddressFamily == AddressFamily.InterNetwork) &&
                   addresses
                       .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                       .All(a => !IsForbiddenIp(a));
        }
        catch
        {
            return false;
        }
    }

    private static bool IsForbiddenIp(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return true;
        var b = address.GetAddressBytes();

        if (b.Length != 4) return true;
        if (b[0] == 0) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        if (b[0] == 100 && b[1] is >= 64 and <= 127) return true;
        if (b[0] >= 224) return true;
        if (b is [255, 255, 255, 255]) return true;
        return false;
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
                if (c is >= '0' and <= '9' or '_') continue;
                return false;
            }
            hasLetter |= labelHasLetter;
        }

        return hasLetter;
    }
}
