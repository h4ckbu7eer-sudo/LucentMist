using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;
using LucentMist.Tools.Common;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

/// <summary>Free-source metadata lookup; a keyword/CPE hit is never an exploit confirmation.</summary>
public class CveApiClient
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        AutomaticDecompression = System.Net.DecompressionMethods.All,
        AllowAutoRedirect = false,
    })
    { Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = 2 * 1024 * 1024 };
    private static readonly ConcurrentDictionary<string, (DateTime ExpiresAt, QueryReport Report)> Cache = new();
    private static readonly SemaphoreSlim Requests = new(6);
    private static readonly object NvdLock = new();
    private static DateTime NextNvdRequest;

    public record CveDetail(string Cve, string Description, double CvssScore, string Source, string Fix,
        string VersionStatus = "unverified", string? VerificationDetail = null, string EvidenceScope = "product", int ReferenceCount = 0);
    public record SourceStatus(string Source, string Status, string Detail, bool Cached = false);
    public record QueryReport(List<CveDetail> Items, SourceStatus[] Sources)
    {
        public bool FellBackToBuiltIn => Sources.Length > 0 && Sources.All(s => s.Status != "ok");
        public bool IsPartial => Sources.Any(s => s.Status != "ok");
    }
    internal sealed record OsvCommitQuery(string Commit, string Evidence);

    internal static bool IsExternalEnabled(string? setting) => string.IsNullOrWhiteSpace(setting)
        || setting.Equals("true", StringComparison.OrdinalIgnoreCase);

    private static string ServiceKey(int port) => port switch
    {
        80 or 443 or 8000 or 8080 or 8443 or 8888 => "http server",
        53 => "dns",
        445 or 139 => "smb",
        22 => "ssh",
        3389 => "rdp",
        _ => PortHelper.GetServiceKey(port) ?? "unknown",
    };

    internal static string[] GetConsultedSources(int port, string? banner, bool externalEnabled)
    {
        if (!externalEnabled || (ServiceKey(port) == "unknown" && ServiceFingerprint.FromBanner(banner) == null)) return [];
        return CreateOsvCommitQuery(banner) == null
            ? ["CVETodo API", "Shodan API", "NVD"]
            : ["CVETodo API", "Shodan API", "NVD", "OSV.dev"];
    }
    internal static string[] GetConsultedSources(int port, string? banner) =>
        GetConsultedSources(port, banner, IsExternalEnabled(Environment.GetEnvironmentVariable("LMIST_CVE_EXTERNAL")));

    public static async Task<List<CveDetail>> QueryAsync(string service, string? version, int port, CancellationToken ct = default) =>
        (await QueryWithStatusAsync(service, version, port, ct)).Items;

    public static Task<QueryReport> QueryWithStatusAsync(string service, string? banner, int port, CancellationToken ct = default) =>
        QueryWithStatusAsync(banner, port, Http,
            IsExternalEnabled(Environment.GetEnvironmentVariable("LMIST_CVE_EXTERNAL")), ct, useCache: true, throttleNvd: true);

    // Never use the caller's target/service string or raw banner in a URL/cache key.
    internal static async Task<QueryReport> QueryWithStatusAsync(string? banner, int port, HttpClient http,
        bool externalEnabled, CancellationToken ct, bool useCache = false, bool throttleNvd = false, TimeSpan? sourceTimeout = null)
    {
        ct.ThrowIfCancellationRequested();
        var sources = GetConsultedSources(port, banner, externalEnabled);
        if (sources.Length == 0) return new([], []);
        var fingerprint = ServiceFingerprint.FromBanner(banner);
        var keyword = fingerprint?.ProductKey ?? ServiceKey(port);
        var commit = CreateOsvCommitQuery(banner);
        var cpe = fingerprint?.Version == null ? null : fingerprint.Cpe;
        var cacheKey = $"{port}|{keyword}|{cpe}|{commit?.Commit}";
        if (useCache && Cache.TryGetValue(cacheKey, out var hit) && hit.ExpiresAt > DateTime.UtcNow)
            return hit.Report with { Items = hit.Report.Items.ToList(), Sources = hit.Report.Sources.Select(s => s with { Cached = true }).ToArray() };

        var responses = await Task.WhenAll(sources.Select((source, index) => Fetch(source, index)));
        var items = responses.SelectMany(r => r.Items).GroupBy(d => d.Cve, StringComparer.OrdinalIgnoreCase).Select(MergeSourceDetails);
        var report = new QueryReport(FilterExternalResultsByBanner(port, banner, items), responses.Select(r => r.Status).ToArray());
        if (useCache)
        {
            Cache[cacheKey] = (DateTime.UtcNow.AddSeconds(report.IsPartial ? 30 : 600), report);
            foreach (var key in Cache.OrderBy(kv => kv.Value.ExpiresAt).Take(Math.Max(0, Cache.Count - 256)).Select(kv => kv.Key))
                Cache.TryRemove(key, out _);
        }
        return report;

        async Task<(List<CveDetail> Items, SourceStatus Status)> Fetch(string source, int index)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(sourceTimeout ?? TimeSpan.FromSeconds(8));
            var entered = false;
            try
            {
                await Requests.WaitAsync(timeout.Token);
                entered = true;
                if (index == 2 && throttleNvd)
                {
                    lock (NvdLock)
                    {
                        // Avoid unbounded waits/retries on the public NVD API.
                        if (DateTime.UtcNow < NextNvdRequest)
                            return ([], new(source, "rate_limited", "NVD 本地节流：至少间隔 6.1 秒；本次跳过，不代表无漏洞"));
                        NextNvdRequest = DateTime.UtcNow.AddSeconds(6.1);
                    }
                }
                var results = index switch
                {
                    0 => await TryCveTodo(keyword, http, timeout.Token),
                    1 => await TryShodanServiceSearch(keyword, cpe, http, timeout.Token),
                    2 => await TryNvdSearch(keyword, cpe, http, timeout.Token),
                    _ => await TryOsvSearch(banner, http, timeout.Token),
                };
                if (results == null) return ([], new(source, "invalid_response", "响应格式不符合接口契约；未取得有效查询结果"));
                results = results.Select(d => d with
                {
                    EvidenceScope = index == 3 ? "commit" : fingerprint == null ? "service_keyword" : "product",
                    VerificationDetail = d.VerificationDetail ?? (fingerprint == null
                        ? "仅协议关键词相关；未识别目标产品或版本，可能完全无关，不计入目标漏洞风险"
                        : "产品关键词/CPE 检索命中；未验证目标版本、配置和发行版补丁；未执行 PoC"),
                }).ToList();
                return (results, new(source, "ok", $"返回 {results.Count} 条（单源截取前 10/OSV 20 条，非完整清单）；" +
                    (index == 3 ? "Git commit 命中，未执行 PoC"
                    : cpe != null && index > 0 ? "按 CPE 检索；配置/发行版补丁未核实，仍为版本未验证候选"
                    : $"按{(fingerprint == null ? "协议服务" : "产品")}关键词检索；版本未验证，可能与目标无关")));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return ([], new(source, "timeout", "外部源超时；继续其他源与内置匹配")); }
            catch (HttpRequestException ex)
            {
                return ([], new(source, ex.StatusCode == System.Net.HttpStatusCode.TooManyRequests ? "rate_limited" : "http_error",
                    ex.StatusCode.HasValue ? $"HTTP {(int)ex.StatusCode.Value}；未取得有效查询结果" : "外部源网络连接失败"));
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
            {
                // No raw payload, request URL or exception message may leak to output.
                return ([], new(source, "invalid_response", "响应格式不符合接口契约；未取得有效查询结果"));
            }
            finally { if (entered) Requests.Release(); }
        }
    }

    internal static CveDetail MergeSourceDetails(IEnumerable<CveDetail> source)
    {
        var details = source.ToList();
        if (details.Count == 0)
            throw new ArgumentException("At least one CVE detail is required.", nameof(source));

        var strongestEvidence = details
            .OrderByDescending(detail =>
                detail.VersionStatus.Equals("verified", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(detail => detail.CvssScore)
            .First();
        var strongestMetadata = details
            .OrderByDescending(detail => detail.CvssScore)
            .First();
        var sources = string.Join(
            " + ",
            details.Select(detail => detail.Source)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase));

        return strongestEvidence with
        {
            Description = strongestMetadata.Description,
            CvssScore = strongestMetadata.CvssScore,
            Source = sources,
            Fix = strongestMetadata.Fix,
            ReferenceCount = details.Max(item => item.ReferenceCount),
        };
    }

    internal static List<CveDetail> FilterExternalResultsByBanner(int port, string? banner, IEnumerable<CveDetail> results)
    {
        var matched = CveDatabase.Match(port, banner).Select(e => e.Cve).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var fingerprint = ServiceFingerprint.FromBanner(banner);
        return results.Where(detail =>
        {
            if (detail.VersionStatus == "verified") return true;
            var known = CveDatabase.Lookup(port).FirstOrDefault(e => e.Cve.Equals(detail.Cve, StringComparison.OrdinalIgnoreCase));
            if (known == null || string.IsNullOrWhiteSpace(banner)) return true;
            if (known.MatchBanner.StartsWith("SMBv", StringComparison.OrdinalIgnoreCase) && banner.Contains("SMBv", StringComparison.OrdinalIgnoreCase))
                return banner.Contains(known.MatchBanner, StringComparison.OrdinalIgnoreCase);
            if (!known.CanMatchBanner || !known.MatchBanner.Contains('<') || fingerprint?.Version == null) return true;
            var product = known.MatchBanner.Split('<')[0].Trim();
            return !product.Equals(fingerprint.ProductKey, StringComparison.OrdinalIgnoreCase) || matched.Contains(detail.Cve);
        }).ToList();
    }

    // ========== CVETodo (服务名搜索) ==========
    private static async Task<List<CveDetail>?> TryCveTodo(string svcKey, HttpClient http, CancellationToken ct)
    {
        try
        {
            var url = $"https://cvetodo.com/api/v1/cves/search?q={Uri.EscapeDataString(svcKey)}&limit=10";
            using var response = await http.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;

            var results = new List<CveDetail>();
            foreach (var item in data.EnumerateArray().Take(10))
            {
                var cveId = item.TryGetProperty("id", out var id) ? id.GetString() ?? "" : item.TryGetProperty("cve_id", out var c) ? c.GetString() ?? "" : "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = item.TryGetProperty("summary", out var s) ? s.GetString() :
                           item.TryGetProperty("description", out var d) ? d.GetString() : null;
                var cvss = 0.0;
                if (item.TryGetProperty("base_score", out var bs) && double.TryParse(bs.ToString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsed)) cvss = parsed;
                else if (item.TryGetProperty("cvss_v3", out var cv3) && cv3.ValueKind == JsonValueKind.Number && cv3.TryGetDouble(out var v3)) cvss = v3;
                else if (item.TryGetProperty("cvss", out var cv) && cv.ValueKind == JsonValueKind.Number && cv.TryGetDouble(out var v)) cvss = v;
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
    private static async Task<List<CveDetail>?> TryShodanServiceSearch(string svcKey, string? cpe, HttpClient http, CancellationToken ct)
    {
        try
        {
            var url = cpe == null ? $"https://cvedb.shodan.io/cves?product={Uri.EscapeDataString(svcKey)}&limit=10" : $"https://cvedb.shodan.io/cves?cpe23={Uri.EscapeDataString(cpe)}&limit=10";
            using var response = await http.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement
                : doc.RootElement.TryGetProperty("cves", out var c) ? c :
                  doc.RootElement.TryGetProperty("results", out var r) ? r : default;

            if (items.ValueKind != JsonValueKind.Array) return null;

            var results = new List<CveDetail>();
            foreach (var item in items.EnumerateArray().Take(10))
            {
                var cveId = item.TryGetProperty("cve", out var cid) ? cid.GetString() :
                            item.TryGetProperty("cve_id", out var ci) ? ci.GetString() :
                            item.TryGetProperty("id", out var id) ? id.GetString() : "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = item.TryGetProperty("summary", out var s) ? s.GetString() :
                           item.TryGetProperty("description", out var d) ? d.GetString() : null;
                var cvss = 0.0;
                if (item.TryGetProperty("base_score", out var bs) && double.TryParse(bs.ToString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var parsed)) cvss = parsed;
                else if (item.TryGetProperty("cvss_v3", out var cv3) && cv3.ValueKind == JsonValueKind.Number && cv3.TryGetDouble(out var v3)) cvss = v3;
                else if (item.TryGetProperty("cvss", out var cv) && cv.ValueKind == JsonValueKind.Number && cv.TryGetDouble(out var v)) cvss = v;
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
    private static async Task<List<CveDetail>?> TryNvdSearch(string service, string? cpe, HttpClient http, CancellationToken ct)
    {
        try
        {
            var url = cpe == null ? $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Uri.EscapeDataString(service)}&resultsPerPage=10" : $"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={Uri.EscapeDataString(cpe)}&resultsPerPage=10";
            using var response = await http.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();

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

                var referenceCount = cveNode.TryGetProperty("references", out var references) && references.ValueKind == JsonValueKind.Array
                    ? references.GetArrayLength() : 0;
                results.Add(new CveDetail(cveId, desc, cvss, "NVD", $"参考 NVD: https://nvd.nist.gov/vuln/detail/{cveId}", ReferenceCount: referenceCount));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }

    // ========== OSV.dev ==========
    internal static async Task<List<CveDetail>?> TryOsvSearch(
        string? evidence,
        HttpClient http,
        CancellationToken ct)
    {
        var query = CreateOsvCommitQuery(evidence);
        if (query == null) return null;
        try
        {
            var body = new { commit = query.Commit };
            using var response = await http.PostAsJsonAsync(
                "https://api.osv.dev/v1/query",
                body,
                ct);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("vulns", out var vulns)) return [];

            var results = new List<CveDetail>();
            foreach (var vuln in vulns.EnumerateArray().Take(20))
            {
                var cveId = "";
                if (vuln.TryGetProperty("aliases", out var aliases))
                    cveId = aliases.EnumerateArray().Select(a => a.GetString())
                        .FirstOrDefault(a => a?.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) == true) ?? "";
                if (string.IsNullOrEmpty(cveId)) continue;
                var desc = vuln.TryGetProperty("summary", out var sum) ? sum.GetString() : "无描述";
                results.Add(new CveDetail(
                    cveId,
                    desc ?? "无描述",
                    0,
                    "OSV.dev",
                    "升级到最新版本",
                    "verified",
                    $"OSV.dev 按{query.Evidence}返回代码命中；未执行 PoC 验证"));
            }
            return results;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (HttpRequestException) { throw; }
        catch (TaskCanceledException) { throw; }
        catch (JsonException) { return null; }
    }

    internal static OsvCommitQuery? CreateOsvCommitQuery(string? evidence)
    {
        if (string.IsNullOrWhiteSpace(evidence)) return null;

        var match = System.Text.RegularExpressions.Regex.Match(
            evidence,
            @"\b(?:git[-_ ]?commit|commit)\s*[:= ]\s*(?<sha>[0-9a-f]{40})\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (!match.Success) return null;

        var commit = match.Groups["sha"].Value.ToLowerInvariant();
        return new OsvCommitQuery(
            commit,
            $"Git commit {commit[..12]}");
    }
}
