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

    // 当前后台任务
    public string CurrentTaskId { get; set; } = "";
    public string CurrentStatus { get; set; } = "";
    public string CurrentMessage { get; set; } = "";
    public int ProgressPercent { get; set; }
    public string? LastError { get; set; }

    // SSL
    public SslState? SslResult { get; set; }

    public record DeviceResult(string Ip, string Ports);
    public record ScanPortResult(int Port, string Service);
    public record SslState(string Target, int Port, bool Expired, int Days, string NotAfter, string Subject, string Issuer, string Fp, int Chain);
}
