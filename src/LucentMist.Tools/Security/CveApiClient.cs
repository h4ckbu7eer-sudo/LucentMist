using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;
using LucentMist.Tools.Common;

namespace LucentMist.Tools.Security;

/// <summary>
/// 多源 CVE API 客户端 — 并行查询，按 CVE ID 去重合并
/// </summary>
public class CveApiClient
{
    private static readonly HttpClient _http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        AutomaticDecompression = System.Net.DecompressionMethods.All,
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
    };

    private static readonly ConcurrentDictionary<string, (DateTime ExpiresAt, List<CveDetail> Items)> Cache = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);

    public record CveDetail(string Cve, string Description, double CvssScore, string Source, string Fix);

    private static string ServiceKey(int port) =>
        PortHelper.GetServiceKey(port) ?? "unknown";

    /// <summary>
    /// 按端口查询所有 API（并行），合并去重。每个 API 失败重试 1 次。
    /// </summary>
    public static async Task<List<CveDetail>> QueryAsync(
        string service,
        string? version,
        int port,
        CancellationToken ct = default)
    {
        if (Environment.GetEnvironmentVariable("LMIST_CVE_EXTERNAL") != "true")
            return [];

        var cacheKey = $"{service}|{version}|{port}";
        if (Cache.TryGetValue(cacheKey, out var hit) && hit.ExpiresAt > DateTime.UtcNow)
            return hit.Items.ToList();

        var svcKey = ServiceKey(port);
        var seen = new HashSet<string>();
        var results = new List<CveDetail>();

        // 并行调用 4 个源（每个带重试）
        var tasks = new Task<List<CveDetail>?>[]
        {
            WithRetry(TryCveTodo, svcKey, "CVETodo", ct),
            WithRetry(TryShodanServiceSearch, svcKey, "Shodan", ct),
            WithRetry(TryNvdSearch, svcKey, "NVD", ct),
            WithRetry((_, token) => TryOsvSearch(service, version, token), "", "OSV", ct),
        };

        var sourceResults = await Task.WhenAll(tasks);

        foreach (var list in sourceResults)
        {
            if (list == null) continue;
            foreach (var cve in list)
            {
                if (seen.Add(cve.Cve))
                    results.Add(cve);
            }
        }

        // API 全部无结果 → 只有抓到具体版本号才回退内置库匹配
        // 绝不按纯端口回退，防止"445 开放就报 EternalBlue"这类系统性误报
        if (results.Count == 0 && !string.IsNullOrWhiteSpace(version))
        {
            foreach (var cve in CveDatabase.Match(port, version))
            {
                results.Add(new CveDetail(cve.Cve, cve.Name,
                    cve.Risk switch { "critical" => 9.8, "high" => 7.5, "medium" => 5.0, _ => 3.0 },
                    "内置库", cve.Fix));
            }
        }

        Cache[cacheKey] = (DateTime.UtcNow.Add(CacheTtl), results);
        PruneCache();
        return results;
    }

    private static void PruneCache()
    {
        if (Cache.Count <= 256) return;

        var expired = Cache
            .Where(kv => kv.Value.ExpiresAt <= DateTime.UtcNow)
            .Select(kv => kv.Key)
            .ToArray();
        foreach (var key in expired)
            Cache.TryRemove(key, out _);

        var excess = Cache.Count - 256;
        if (excess <= 0) return;
        foreach (var key in Cache
                     .OrderBy(kv => kv.Value.ExpiresAt)
                     .Take(excess)
                     .Select(kv => kv.Key))
        {
            Cache.TryRemove(key, out _);
        }
    }

    private static async Task<List<CveDetail>?> WithRetry(
        Func<string, CancellationToken, Task<List<CveDetail>?>> fn,
        string argument,
        string source,
        CancellationToken ct)
    {
        try { return await fn(argument, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogSourceFailure(source, ex); await Task.Delay(500, ct); }
        try { return await fn(argument, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogSourceFailure(source, ex); return null; }
    }

    private static void LogSourceFailure(string source, Exception ex)
    {
        if (Environment.GetEnvironmentVariable("LMIST_CVE_DEBUG") != "true") return;
        Console.Error.WriteLine($"[CVE:{source}] {ex.GetType().Name}: {ex.Message}");
    }

    // ========== CVETodo (服务名搜索) ==========
    private static async Task<List<CveDetail>?> TryCveTodo(string svcKey, CancellationToken ct)
    {
        try
        {
            var url = $"https://cvetodo.com/api/v1/cves/search?q={svcKey}";
            using var response = await _http.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;

            var results = new List<CveDetail>();
            foreach (var item in data.EnumerateArray().Take(10))
            {
                var cveId = item.TryGetProperty("cve_id", out var c) ? c.GetString() ?? "" : "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = item.TryGetProperty("summary", out var s) ? s.GetString() :
                           item.TryGetProperty("description", out var d) ? d.GetString() : null;
                var cvss = 0.0;
                if (item.TryGetProperty("cvss_v3", out var cv3) && cv3.TryGetDouble(out var v3)) cvss = v3;
                else if (item.TryGetProperty("cvss", out var cv) && cv.TryGetDouble(out var v)) cvss = v;
                results.Add(new CveDetail(cveId, desc ?? "无描述", cvss, "CVETodo API", "参考官方公告"));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }

    // ========== Shodan CVEDB (服务名搜索) ==========
    private static async Task<List<CveDetail>?> TryShodanServiceSearch(string svcKey, CancellationToken ct)
    {
        try
        {
            var url = $"https://cvedb.shodan.io/cves?query={svcKey}";
            using var response = await _http.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement
                : doc.RootElement.TryGetProperty("cves", out var c) ? c :
                  doc.RootElement.TryGetProperty("results", out var r) ? r : default;

            if (items.ValueKind != JsonValueKind.Array) return null;

            var results = new List<CveDetail>();
            foreach (var item in items.EnumerateArray().Take(15))
            {
                var cveId = item.TryGetProperty("cve", out var cid) ? cid.GetString() :
                            item.TryGetProperty("cve_id", out var ci) ? ci.GetString() :
                            item.TryGetProperty("id", out var id) ? id.GetString() : "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = item.TryGetProperty("summary", out var s) ? s.GetString() :
                           item.TryGetProperty("description", out var d) ? d.GetString() : null;
                var cvss = 0.0;
                if (item.TryGetProperty("cvss_v3", out var cv3) && cv3.TryGetDouble(out var v3)) cvss = v3;
                else if (item.TryGetProperty("cvss", out var cv) && cv.TryGetDouble(out var v)) cvss = v;
                results.Add(new CveDetail(cveId, desc ?? "无描述", cvss, "Shodan API", "参考官方公告"));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }

    // ========== NVD (NIST) ==========
    private static async Task<List<CveDetail>?> TryNvdSearch(string service, CancellationToken ct)
    {
        try
        {
            var url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(service)}&resultsPerPage=5";
            using var response = await _http.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns)) return null;

            var results = new List<CveDetail>();
            foreach (var v in vulns.EnumerateArray())
            {
                var cveNode = v.TryGetProperty("cve", out var cn) ? cn : default;
                var cveId = cveNode.TryGetProperty("id", out var cid) ? cid.GetString() ?? "" : "";
                if (string.IsNullOrEmpty(cveId)) continue;

                var desc = "";
                if (cveNode.TryGetProperty("descriptions", out var descs))
                {
                    foreach (var d in descs.EnumerateArray())
                    {
                        if (d.TryGetProperty("lang", out var lang) && lang.GetString() == "en")
                            desc = d.TryGetProperty("value", out var val) ? val.GetString() ?? "" : "";
                    }
                }

                var cvss = 0.0;
                if (cveNode.TryGetProperty("metrics", out var metrics))
                {
                    if (metrics.TryGetProperty("cvssMetricV31", out var cvss31))
                    {
                        var first = cvss31.EnumerateArray().FirstOrDefault();
                        if (first.TryGetProperty("cvssData", out var cd) && cd.TryGetProperty("baseScore", out var bs))
                            bs.TryGetDouble(out cvss);
                    }
                    else if (metrics.TryGetProperty("cvssMetricV30", out var cvss30))
                    {
                        var first = cvss30.EnumerateArray().FirstOrDefault();
                        if (first.TryGetProperty("cvssData", out var cd) && cd.TryGetProperty("baseScore", out var bs))
                            bs.TryGetDouble(out cvss);
                    }
                }

                results.Add(new CveDetail(cveId, desc, cvss, "NVD", $"参考 NVD: https://nvd.nist.gov/vuln/detail/{cveId}"));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }

    // ========== OSV.dev ==========
    private static async Task<List<CveDetail>?> TryOsvSearch(
        string service,
        string? banner,
        CancellationToken ct)
    {
        var version = CveDatabase.ExtractVersion(banner ?? "");
        if (string.IsNullOrEmpty(version)) return null;
        try
        {
            var pkgName = service.ToLower() switch
            {
                "ssh" => "openssh",
                "smb" => "samba",
                "http" => "nginx",
                "rdp" => "xrdp",
                "mysql" => "mysql-server",
                "redis" => "redis",
                _ => service.ToLower()
            };
            var body = new { package = new { name = pkgName, ecosystem = "Debian" }, version };
            using var response = await _http.PostAsJsonAsync(
                "https://api.osv.dev/v1/query",
                body,
                ct);
            if (!response.IsSuccessStatusCode) return null;

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vulns", out var vulns)) return null;

            var results = new List<CveDetail>();
            foreach (var vuln in vulns.EnumerateArray().Take(20))
            {
                var cveId = "";
                if (vuln.TryGetProperty("aliases", out var aliases))
                    cveId = aliases.EnumerateArray().Select(a => a.GetString())
                        .FirstOrDefault(a => a?.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) == true) ?? "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = vuln.TryGetProperty("summary", out var sum) ? sum.GetString() : "无描述";
                results.Add(new CveDetail(cveId, desc ?? "无描述", 0, "OSV.dev", "升级到最新版本"));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }
}
