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
    public async Task<bool> CheckAvailabilityAsync(CancellationToken ct = default)
    {
        if (!_enabled)
        {
            IsAvailable = false;
            return false;
        }

        try
        {
            using var resp = await _http.GetAsync("/health", ct);
            IsAvailable = resp.IsSuccessStatusCode;
            if (!IsAvailable) ErrorMessage = $"Sirius 响应异常: HTTP {resp.StatusCode}";
            return IsAvailable;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
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
    public async Task<SiriusScanResponse?> SubmitScanAsync(
        string target,
        string[]? ports = null,
        int timeout = 300,
        CancellationToken ct = default)
    {
        if (!_enabled) { ErrorMessage = "Sirius 已禁用"; return null; }
        try
        {
            var body = new SiriusScanRequest(target, ports, timeout);
            using var resp = await _http.PostAsJsonAsync("/api/v1/scan", body, ct);
            return resp.IsSuccessStatusCode
                ? await resp.Content.ReadFromJsonAsync<SiriusScanResponse>(ct)
                : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { ErrorMessage = ex.Message; return null; }
    }

    /// <summary>
    /// 查询扫描状态
    /// </summary>
    public async Task<SiriusTaskStatus?> GetTaskStatusAsync(
        string taskId,
        CancellationToken ct = default)
    {
        try
        {
            var id = Uri.EscapeDataString(taskId);
            using var resp = await _http.GetAsync($"/api/v1/scan/{id}", ct);
            return resp.IsSuccessStatusCode
                ? await resp.Content.ReadFromJsonAsync<SiriusTaskStatus>(ct)
                : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>
    /// 获取扫描结果
    /// </summary>
    public async Task<SiriusResult?> GetResultAsync(
        string taskId,
        CancellationToken ct = default)
    {
        try
        {
            var id = Uri.EscapeDataString(taskId);
            using var resp = await _http.GetAsync($"/api/v1/scan/{id}/result", ct);
            return resp.IsSuccessStatusCode
                ? await resp.Content.ReadFromJsonAsync<SiriusResult>(ct)
                : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>
    /// 执行完整扫描（提交 + 轮询 + 获取结果）
    /// </summary>
    public async Task<(SiriusResult? Result, string? Error)> RunScanAsync(
        string target, Action<string, int>? onProgress = null, CancellationToken ct = default)
    {
        if (!await CheckAvailabilityAsync(ct))
            return (null, ErrorMessage);

        var submit = await SubmitScanAsync(target, ct: ct);
        if (submit == null)
            return (null, "提交扫描任务失败");

        onProgress?.Invoke($"任务 {submit.TaskId} 已提交", 10);

        // Poll for completion
        var maxWait = TimeSpan.FromMinutes(5);
        var start = DateTime.UtcNow;
        var completed = false;
        while (DateTime.UtcNow - start < maxWait && !ct.IsCancellationRequested)
        {
            var status = await GetTaskStatusAsync(submit.TaskId, ct);
            if (status == null) return (null, "查询扫描状态失败");

            onProgress?.Invoke(status.Message ?? $"进度 {status.Progress}%", status.Progress);

            if (status.Status is "completed" or "done")
            {
                completed = true;
                break;
            }
            if (status.Status is "failed" or "error")
                return (null, status.Message ?? "扫描失败");

            await Task.Delay(2000, ct);
        }

        ct.ThrowIfCancellationRequested();
        if (!completed)
            return (null, $"扫描在 {maxWait.TotalMinutes:0} 分钟内未完成");

        onProgress?.Invoke("正在获取结果...", 90);
        var result = await GetResultAsync(submit.TaskId, ct);
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
            GeneratedAt = DateTime.Now,
            ScanStatus = "completed",
            StatusMessage = "Sirius 扫描已完成",
            Scope = new()
            {
                Discovery = "由 Sirius/Nmap 执行目标发现",
                TcpPorts = "由 Sirius 任务配置决定",
                VulnerabilityChecks = "Sirius/Nmap NSE 与其配置的漏洞检测",
                Limitations = "检测范围取决于 Sirius 任务配置；未命中不等于穷尽式安全证明"
            }
        };

        var allVulns = new List<Reporting.ReportGenerator.VulnFinding>();

        foreach (var host in result.Hosts)
        {
            if (host.IsUp) { report.OnlineDevices++; report.TotalDevices++; }
            else { report.TotalDevices++; continue; }

            report.Devices.Add(new() { Ip = host.Ip, IsAlive = true, OsGuess = host.OsGuess ?? "" });

            foreach (var port in host.Ports)
            {
                if (port.State == "open")
                    report.OpenPorts.Add(new() { Target = host.Ip, Port = port.Port, Service = port.Service });

                foreach (var v in port.Vulns)
                {
                    allVulns.Add(new()
                    {
                        Target = host.Ip,
                        Port = port.Port,
                        Service = port.Service,
                        Risk = v.Risk,
                        Cve = v.Cve,
                        Cvss = v.Cvss,
                        Source = "Sirius Scan",
                        Confirmed = v.Verified,
                        VerificationDetail = v.Verified
                            ? "Sirius 标记为已验证"
                            : "Sirius 未标记为已验证",
                        Description = $"{v.Name}: {v.Description}",
                        Fix = v.Fix
                    });
                }
            }
        }

        report.VulnInfo = Reporting.ReportGenerator.BuildVulnerabilitySummary(allVulns);
        if (report.OnlineDevices == 0)
        {
            report.ScanStatus = "no_targets";
            report.StatusMessage = "Sirius 未发现在线设备；无法得出安全结论";
            report.Warnings.Add("未执行有效的端口或漏洞检测");
            report.VulnInfo = null;
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
    public async Task<List<HostInfo>?> GetHostsAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("/host", ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<List<HostInfo>>(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>获取主机详情（含端口和漏洞）</summary>
    public async Task<HostDetail?> GetHostDetailAsync(string hid, CancellationToken ct = default)
    {
        try
        {
            var id = Uri.EscapeDataString(hid);
            using var resp = await _http.GetAsync($"/host/{id}", ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<HostDetail>(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>查询漏洞（POST /vulnerability）</summary>
    public async Task<JsonElement?> QueryVulnerabilitiesAsync(
        string? hostId = null,
        string? cve = null,
        CancellationToken ct = default)
    {
        try
        {
            var body = new Dictionary<string, object>();
            if (hostId != null) body["host_id"] = hostId;
            if (cve != null) body["cve"] = cve;
            using var resp = await _http.PostAsJsonAsync("/vulnerability", body, ct);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync(ct);
            return JsonDocument.Parse(json).RootElement;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>获取扫描任务状态（解析 /host 列表中的最新扫描）</summary>
    public async Task<List<HostInfo>?> GetScansAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("/host", ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<List<HostInfo>>(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    public void Dispose() => _http.Dispose();
}
