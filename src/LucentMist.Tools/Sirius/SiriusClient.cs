using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace LucentMist.Tools.Sirius;

/// <summary>
/// Sirius Scan API 客户端 — 集成外部漏洞扫描器
/// </summary>
public class SiriusClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly bool _enabled;

    public bool IsAvailable { get; private set; }
    public string ErrorMessage { get; private set; } = "";

    public SiriusClient(string? apiUrl = null, string? apiKey = null, HttpClient? http = null)
    {
        apiUrl ??= Environment.GetEnvironmentVariable("SIRIUS_API_URL") ?? "http://localhost:9001";
        apiKey ??= Environment.GetEnvironmentVariable("SIRIUS_API_KEY");

        _baseUrl = apiUrl.TrimEnd('/');
        _http = http ?? new HttpClient();
        if (_http.BaseAddress == null)
            _http.BaseAddress = new Uri(_baseUrl);
        _http.Timeout = TimeSpan.FromSeconds(30);

        // 未配置密钥 → 禁用集成，而不是抛异常（避免拖垮 Ollama 模式的 agent）
        if (string.IsNullOrEmpty(apiKey))
        {
            _enabled = false;
            ErrorMessage = "SIRIUS_API_KEY 未配置，Sirius 集成已禁用";
            IsAvailable = false;
            return;
        }

        _enabled = true;
        if (!_http.DefaultRequestHeaders.Contains("X-API-Key"))
            _http.DefaultRequestHeaders.Add("X-API-Key", apiKey);
    }

    /// <summary>
    /// 验证 Sirius 服务是否可用
    /// </summary>
    public async Task<bool> CheckAvailabilityAsync()
    {
        if (!_enabled)
        {
            IsAvailable = false;
            return false;
        }

        try
        {
            using var resp = await _http.GetAsync("/health");
            IsAvailable = resp.IsSuccessStatusCode;
            if (!IsAvailable) ErrorMessage = $"Sirius 响应异常: HTTP {resp.StatusCode}";
            return IsAvailable;
        }
        catch
        {
            IsAvailable = false;
            ErrorMessage = $"Sirius 服务未启动 ({_baseUrl})。\n请运行: cd Sirius && docker compose up -d";
            return false;
        }
    }

    /// <summary>
    /// 提交扫描任务
    /// </summary>
    public async Task<SiriusScanResponse?> SubmitScanAsync(string target, string[]? ports = null, int timeout = 300)
    {
        if (!_enabled) { ErrorMessage = "Sirius 已禁用"; return null; }
        try
        {
            var body = new SiriusScanRequest(target, ports, timeout);
            using var resp = await _http.PostAsJsonAsync("/api/v1/scan", body);
            return resp.IsSuccessStatusCode ? await resp.Content.ReadFromJsonAsync<SiriusScanResponse>() : null;
        }
        catch (Exception ex) { ErrorMessage = ex.Message; return null; }
    }

    /// <summary>
    /// 查询扫描状态
    /// </summary>
    public async Task<SiriusTaskStatus?> GetTaskStatusAsync(string taskId)
    {
        try
        {
            using var resp = await _http.GetAsync($"/api/v1/scan/{taskId}");
            return resp.IsSuccessStatusCode ? await resp.Content.ReadFromJsonAsync<SiriusTaskStatus>() : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// 获取扫描结果
    /// </summary>
    public async Task<SiriusResult?> GetResultAsync(string taskId)
    {
        try
        {
            using var resp = await _http.GetAsync($"/api/v1/scan/{taskId}/result");
            return resp.IsSuccessStatusCode ? await resp.Content.ReadFromJsonAsync<SiriusResult>() : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// 执行完整扫描（提交 + 轮询 + 获取结果）
    /// </summary>
    public async Task<(SiriusResult? Result, string? Error)> RunScanAsync(
        string target, Action<string, int>? onProgress = null, CancellationToken ct = default)
    {
        if (!await CheckAvailabilityAsync())
            return (null, ErrorMessage);

        var submit = await SubmitScanAsync(target);
        if (submit == null)
            return (null, "提交扫描任务失败");

        onProgress?.Invoke($"任务 {submit.TaskId} 已提交", 10);

        // Poll for completion
        var maxWait = TimeSpan.FromMinutes(5);
        var start = DateTime.UtcNow;
        while (DateTime.UtcNow - start < maxWait && !ct.IsCancellationRequested)
        {
            var status = await GetTaskStatusAsync(submit.TaskId);
            if (status == null) break;

            onProgress?.Invoke(status.Message ?? $"进度 {status.Progress}%", status.Progress);

            if (status.Status is "completed" or "done")
                break;
            if (status.Status is "failed" or "error")
                return (null, status.Message ?? "扫描失败");

            await Task.Delay(2000, ct);
        }

        onProgress?.Invoke("正在获取结果...", 90);
        var result = await GetResultAsync(submit.TaskId);
        return result != null ? (result, null) : (null, "获取扫描结果失败");
    }

    /// <summary>
    /// 将 Sirius 结果转换为内部的 ReportGenerator 报告格式
    /// </summary>
    public static Reporting.ReportGenerator.ScanReport ConvertToReport(SiriusResult result)
    {
        var report = new Reporting.ReportGenerator.ScanReport
        {
            Title = $"LucentMist 扫描报告 (Sirius Scan)",
            Target = result.Target,
            ScanDuration = result.ScanDuration,
            GeneratedAt = DateTime.Now
        };

        foreach (var host in result.Hosts)
        {
            if (host.IsUp) { report.OnlineDevices++; report.TotalDevices++; }
            else { report.TotalDevices++; continue; }

            report.Devices.Add(new() { Ip = host.Ip, IsAlive = true, OsGuess = host.OsGuess ?? "" });

            var vulns = new List<Reporting.ReportGenerator.VulnFinding>();
            foreach (var port in host.Ports)
            {
                if (port.State == "open")
                    report.OpenPorts.Add(new() { Target = host.Ip, Port = port.Port, Service = port.Service });

                foreach (var v in port.Vulns)
                {
                    vulns.Add(new()
                    {
                        Port = port.Port,
                        Service = port.Service,
                        Risk = v.Risk,
                        Description = $"{v.Name} ({v.Cve}): {v.Description}",
                        Fix = v.Fix
                    });
                }
            }

            if (vulns.Count > 0)
            {
                report.VulnInfo = new()
                {
                    OverallRisk = vulns.Any(v => v.Risk == "critical") ? "严重" :
                                  vulns.Any(v => v.Risk == "high") ? "高" :
                                  vulns.Any(v => v.Risk == "medium") ? "中" : "低",
                    CriticalCount = vulns.Count(v => v.Risk == "critical"),
                    HighCount = vulns.Count(v => v.Risk == "high"),
                    MediumCount = vulns.Count(v => v.Risk == "medium"),
                    LowCount = vulns.Count(v => v.Risk == "low"),
                    Findings = vulns
                };
            }
        }

        return report;
    }

    // ========== Sirius API 方法（实际路由） ==========

    public record HostInfo(string Hid, string Os, string? OsVersion, string? Ip, string? Hostname, string? Status,
        string? FirstSeen, string? LastSeen, List<HostPort>? Ports = null);

    public record HostDetail(string Hid, string Os, string? OsVersion, string? Ip, List<HostPort>? Ports);

    public record HostPort(int Number, string Protocol, string State, string? Service = null);

    public record VulnFinding(string Cve, string Name, string Risk, double Cvss, string Description, string Fix, bool Verified);

    /// <summary>获取所有主机列表</summary>
    public async Task<List<HostInfo>?> GetHostsAsync()
    {
        try
        {
            using var resp = await _http.GetAsync("/host");
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<List<HostInfo>>();
        }
        catch { return null; }
    }

    /// <summary>获取主机详情（含端口和漏洞）</summary>
    public async Task<HostDetail?> GetHostDetailAsync(string hid)
    {
        try
        {
            using var resp = await _http.GetAsync($"/host/{hid}");
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<HostDetail>();
        }
        catch { return null; }
    }

    /// <summary>查询漏洞（POST /vulnerability）</summary>
    public async Task<JsonElement?> QueryVulnerabilitiesAsync(string? hostId = null, string? cve = null)
    {
        try
        {
            var body = new Dictionary<string, object>();
            if (hostId != null) body["host_id"] = hostId;
            if (cve != null) body["cve"] = cve;
            using var resp = await _http.PostAsJsonAsync("/vulnerability", body);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync();
            return JsonDocument.Parse(json).RootElement;
        }
        catch { return null; }
    }

    /// <summary>获取扫描任务状态（解析 /host 列表中的最新扫描）</summary>
    public async Task<List<HostInfo>?> GetScansAsync()
    {
        try
        {
            using var resp = await _http.GetAsync("/host");
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<List<HostInfo>>();
        }
        catch { return null; }
    }

    public void Dispose() => _http.Dispose();
}
