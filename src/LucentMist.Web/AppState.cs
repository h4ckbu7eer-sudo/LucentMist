using System.Text.Json;

namespace LucentMist.Web;

/// <summary>
/// 全局状态 — 跨页面保留扫描结果，导航不丢失
/// </summary>
public class AppState
{
    // 仪表板
    public int OnlineDevices { get; set; }
    public int ScanCount { get; set; }
    public string LastScanTarget { get; set; } = "—";
    public List<DeviceResult> LastResults { get; set; } = new();

    // 设备列表
    public List<DeviceResult> Devices { get; set; } = new();
    public string DeviceScanTarget { get; set; } = "127.0.0.1";

    // 扫描控制
    public List<ScanPortResult> ScanResults { get; set; } = new();
    public string ScanResultTarget { get; set; } = "";
    public int ScanResultTotal { get; set; }
    public int ScanResultOpen { get; set; }
    public bool HasScanResult { get; set; }
    public string ScanTarget { get; set; } = "127.0.0.1";
    public string ScanPorts { get; set; } = "1-1000";
    public string ScanType { get; set; } = "tcp";
    public string LlmProvider { get; set; } = "Ollama";

    // SSL
    public SslState? SslResult { get; set; }

    public record DeviceResult(string Ip, string Ports);
    public static string DescribeDevicePorts(JsonElement root, string ip)
    {
        if (root.TryGetProperty("portScanFailures", out var failures) && failures.TryGetProperty(ip, out _))
            return "端口扫描失败，无法确认";
        if (!root.TryGetProperty("openPortsByIp", out var map) || !map.TryGetProperty(ip, out var ports))
            return "未取得端口结果（未检查或历史数据缺失）";
        var open = ports.EnumerateArray().Select(p => p.GetInt32()).ToArray();
        return open.Length > 0 ? string.Join(',', open) : "所选端口未观测到开放";
    }
    public record ScanPortResult(int Port, string Service, string State = "open", string Detail = "")
    {
        public string StatusLabel => State switch
        {
            "open" => "开放（已响应）",
            "closed" => "关闭（不可达/重置推断）",
            "alive" => "在线",
            "unprobeable" => "无法确认（无有效探测方式）",
            "open|filtered" => "无法确认（开放或被过滤）",
            _ => "无法确认"
        };

        public static IReadOnlyList<ScanPortResult> FromToolResult(JsonElement root, string scanType)
        {
            if (scanType == "udp" && root.TryGetProperty("ports", out var states) && states.ValueKind == JsonValueKind.Array)
                return states.EnumerateArray().Select(p => new ScanPortResult(
                    p.GetProperty("port").GetInt32(),
                    p.TryGetProperty("service", out var svc) ? svc.GetString() ?? "未知" : "未知",
                    p.TryGetProperty("state", out var state) ? state.GetString() ?? "unknown" : "unknown",
                    p.TryGetProperty("detail", out var detail) ? detail.GetString() ?? "" : "")).ToArray();
            if (!root.TryGetProperty("openPorts", out var ports)) return [];
            return ports.EnumerateArray().Select(p =>
            {
                var port = p.GetInt32();
                var service = scanType == "udp"
                    ? LucentMist.Tools.Common.PortHelper.GetUdpServiceName(port)
                    : LucentMist.Tools.Common.PortHelper.GetTcpServiceName(port);
                return new ScanPortResult(port, service ?? "未知");
            }).ToArray();
        }
    }
    public record SslState(
        string Target,
        int Port,
        bool Expired,
        bool Trusted,
        int Days,
        string NotAfter,
        string Subject,
        string Issuer,
        string Fp,
        int Chain,
        IReadOnlyList<string> TrustExplanations)
    {
        public string StatusLabel => Expired
            ? "已过期"
            : Trusted ? "有效且受信任" : "有效期内但不受信任";

        public static SslState FromToolResult(JsonElement value) => new(
            value.GetProperty("target").GetString()!,
            value.GetProperty("port").GetInt32(),
            value.GetProperty("isExpired").GetBoolean(),
            value.TryGetProperty("isTrusted", out var trusted) && trusted.GetBoolean(),
            value.GetProperty("daysRemaining").GetInt32(),
            value.GetProperty("notAfter").GetString() ?? "-",
            value.GetProperty("subject").GetString() ?? "-",
            value.GetProperty("issuer").GetString() ?? "-",
            value.TryGetProperty("thumbprintSha256", out var thumbprint) ? thumbprint.GetString() ?? "-" : "-",
            value.TryGetProperty("chain", out var chain) ? chain.GetArrayLength() : 0,
            ReadTrustExplanations(value));

        private static IReadOnlyList<string> ReadTrustExplanations(JsonElement value)
        {
            var property = value.TryGetProperty("trustExplanations", out var explanations)
                ? explanations
                : value.TryGetProperty("trustErrors", out var errors) ? errors : default;
            return property.ValueKind == JsonValueKind.Array
                ? property.EnumerateArray()
                    .Select(item => item.GetString())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Cast<string>()
                    .ToArray()
                : [];
        }
    }
}
