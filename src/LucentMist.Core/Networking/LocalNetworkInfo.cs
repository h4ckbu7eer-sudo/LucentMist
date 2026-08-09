using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LucentMist.Core.Networking;

public record LocalNetworkEntry(string Name, string Ip, int Prefix, string Gateway);

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

            var props = nic.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4 == null) continue;

            var ip = ipv4.Address.ToString();
            if (ip == "127.0.0.1") continue;

            var mask = ipv4.IPv4Mask?.ToString();
            var prefix = mask != null ? MaskToPrefix(mask) : 24;
            var gateway = props.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                ?.Address.ToString() ?? "未知";

            results.Add(new LocalNetworkEntry(nic.Name, ip, prefix, gateway));
        }

        return results;
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
