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
    public string ScanTarget { get; set; } = "127.0.0.1";
    public string ScanPorts { get; set; } = "1-1000";
    public string ScanType { get; set; } = "tcp";
    public string LlmProvider { get; set; } = "Ollama";

    // SSL
    public SslState? SslResult { get; set; }

    public record DeviceResult(string Ip, string Ports);
    public record ScanPortResult(int Port, string Service);
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
