using System.Text;
using System.Text.Json;

namespace LucentMist.Tools.Reporting;

public class ReportGenerator
{
    public enum Format { Json, Html, Markdown, Csv }

    public class ScanReport
    {
        public string Title { get; set; } = "LucentMist 扫描报告";
        public string Target { get; set; } = "";
        public DateTime GeneratedAt { get; set; } = DateTime.Now;
        public string ScanDuration { get; set; } = "";
        public int TotalDevices { get; set; }
        public int OnlineDevices { get; set; }
        public string ScanStatus { get; set; } = "not_scanned";
        public string StatusMessage { get; set; } = "扫描尚未完成";
        public ScanScope Scope { get; set; } = new();
        /// <summary>会影响暴露面或漏洞结论完整性的警告。</summary>
        public List<string> Warnings { get; set; } = new();
        /// <summary>不影响结论完整性的补充说明。</summary>
        public List<string> Notes { get; set; } = new();
        public List<DeviceEntry> Devices { get; set; } = new();
        public List<PortEntry> OpenPorts { get; set; } = new();
        public List<SslEntry> SslInfo { get; set; } = new();
        public VulnSummary? VulnInfo { get; set; }
    }
    public class DeviceEntry { public string Ip { get; set; } = ""; public bool IsAlive { get; set; } public string OsGuess { get; set; } = ""; }
    public class PortEntry { public string Target { get; set; } = ""; public int Port { get; set; } public string Service { get; set; } = ""; public string State { get; set; } = "open"; }
    public class SslEntry { public string Target { get; set; } = ""; public int Port { get; set; } public string Subject { get; set; } = ""; public string Issuer { get; set; } = ""; public string NotAfter { get; set; } = ""; public int DaysRemaining { get; set; } public bool IsExpired { get; set; } public List<string> TrustErrors { get; set; } = new(); }
    public class ScanScope { public string Discovery { get; set; } = "未记录"; public string TcpPorts { get; set; } = "未记录"; public string VulnerabilityChecks { get; set; } = "未记录"; public string Limitations { get; set; } = "扫描结果不代表穷尽式安全证明"; }
    public class VulnSummary { public string OverallRisk { get; set; } = "安全"; public int CriticalCount { get; set; } public int HighCount { get; set; } public int MediumCount { get; set; } public int LowCount { get; set; } public List<VulnFinding> Findings { get; set; } = new(); }
    public class VulnFinding
    {
        public string Target { get; set; } = "";
        public int Port { get; set; }
        public string Service { get; set; } = "";
        public string Cve { get; set; } = "";
        public string Risk { get; set; } = "";
        public double? Cvss { get; set; }
        public string Source { get; set; } = "";
        public bool Confirmed { get; set; }
        public string Banner { get; set; } = "";
        public string VerificationDetail { get; set; } = "";
        public string Description { get; set; } = "";
        public string Fix { get; set; } = "";
    }

    public static VulnFinding ParseVulnerabilityFinding(string target, JsonElement finding) => new()
    {
        Target = target,
        Port = finding.TryGetProperty("port", out var port) ? port.GetInt32() : 0,
        Service = finding.TryGetProperty("service", out var service) ? service.GetString() ?? "" : "",
        Cve = finding.TryGetProperty("cve", out var cve) ? cve.GetString() ?? "" : "",
        Risk = finding.TryGetProperty("risk", out var risk) ? risk.GetString() ?? "" : "",
        Cvss = finding.TryGetProperty("cvss", out var cvss) && cvss.TryGetDouble(out var score) ? score : null,
        Source = finding.TryGetProperty("source", out var source) ? source.GetString() ?? "" : "",
        Confirmed = finding.TryGetProperty("confirmed", out var confirmed) && confirmed.GetBoolean(),
        Banner = finding.TryGetProperty("banner", out var banner) ? banner.GetString() ?? "" : "",
        VerificationDetail = finding.TryGetProperty("verificationDetail", out var detail) ? detail.GetString() ?? "" : "",
        Description = finding.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "",
        Fix = finding.TryGetProperty("fix", out var fix) ? fix.GetString() ?? "" : ""
    };

    public static VulnSummary BuildVulnerabilitySummary(IEnumerable<VulnFinding> source)
    {
        var findings = source
            .OrderBy(f => f.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Port)
            .ThenBy(f => f.Cve, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var critical = findings.Count(f => NormalizeRisk(f.Risk) == "critical");
        var high = findings.Count(f => NormalizeRisk(f.Risk) == "high");
        var medium = findings.Count(f => NormalizeRisk(f.Risk) == "medium");
        var low = findings.Count - critical - high - medium;
        return new VulnSummary
        {
            OverallRisk = critical > 0 ? "严重" : high > 0 ? "高" : medium > 0 ? "中" : low > 0 ? "低" : "安全",
            CriticalCount = critical,
            HighCount = high,
            MediumCount = medium,
            LowCount = low,
            Findings = findings
        };
    }

    public static void ApplyCompletionStatus(ScanReport report, int scannedDevices)
    {
        report.ScanStatus = report.Warnings.Count == 0 ? "completed" : "partial";
        report.StatusMessage = report.ScanStatus == "completed"
            ? $"已完成 {scannedDevices} 台在线设备的端口与漏洞候选检测"
            : $"已扫描 {scannedDevices} 台在线设备，但关键阶段失败，结果不完整";
    }

    public string Generate(ScanReport r, Format f) => f switch
    {
        Format.Json => ToJson(r),
        Format.Html => ToHtml(r),
        Format.Markdown => ToMarkdown(r),
        Format.Csv => ToCsv(r),
        _ => ToJson(r)
    };

    private static string ToJson(ScanReport r) => JsonSerializer.Serialize(r,
        new JsonSerializerOptions { WriteIndented = true });

    // ==================== CSV ====================
    private static string ToCsv(ScanReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("记录类型,目标,端口,服务,状态,CVE,风险,CVSS,描述,修复建议,来源");
        sb.AppendLine(string.Join(",",
            CsvEscape("扫描状态"), CsvEscape(r.Target), "", "", CsvEscape(r.ScanStatus),
            "", "", "", CsvEscape(r.StatusMessage), "", ""));
        sb.AppendLine(string.Join(",",
            CsvEscape("扫描范围"), CsvEscape(r.Target), "", CsvEscape("TCP"), "", "", "", "",
            CsvEscape($"发现: {r.Scope.Discovery}; TCP: {r.Scope.TcpPorts}; 漏洞: {r.Scope.VulnerabilityChecks}"),
            CsvEscape(r.Scope.Limitations), ""));
        foreach (var warning in r.Warnings)
            sb.AppendLine(string.Join(",",
                CsvEscape("完整性警告"), CsvEscape(r.Target), "", "", CsvEscape("partial"),
                "", "", "", CsvEscape(warning), "", ""));
        foreach (var note in r.Notes)
            sb.AppendLine(string.Join(",",
                CsvEscape("补充说明"), CsvEscape(r.Target), "", "", CsvEscape("note"),
                "", "", "", CsvEscape(note), "", ""));
        foreach (var port in r.OpenPorts)
        {
            sb.AppendLine(string.Join(",",
                CsvEscape("开放端口"),
                CsvEscape(port.Target),
                port.Port,
                CsvEscape(port.Service),
                CsvEscape(port.State),
                CsvEscape("-"),
                CsvEscape("-"),
                CsvEscape("-"),
                CsvEscape($"目标对外提供 {port.Service} 服务"),
                CsvEscape(PortAdvice(port)),
                CsvEscape("端口扫描")));
        }

        foreach (var ssl in r.SslInfo)
        {
            var (state, _) = SslStatus(ssl);
            sb.AppendLine(string.Join(",",
                CsvEscape("TLS 证书"),
                CsvEscape(ssl.Target),
                ssl.Port,
                CsvEscape("TLS"),
                CsvEscape(state),
                CsvEscape("-"),
                CsvEscape(ssl.IsExpired ? "high" : ssl.TrustErrors.Count > 0 || ssl.DaysRemaining <= 30 ? "medium" : "low"),
                CsvEscape("-"),
                CsvEscape($"主体: {ssl.Subject}; 签发者: {ssl.Issuer}; 到期: {ssl.NotAfter}; 信任错误: {TrustErrorLabel(ssl)}"),
                CsvEscape(SslAdvice(ssl)),
                CsvEscape("TLS 检查")));
        }

        if (r.VulnInfo?.Findings != null)
            foreach (var f in r.VulnInfo.Findings)
                sb.AppendLine(string.Join(",",
                    CsvEscape("漏洞"),
                    CsvEscape(f.Target),
                    f.Port,
                    CsvEscape(f.Service),
                    CsvEscape(f.Confirmed ? "已验证" : "候选"),
                    CsvEscape(string.IsNullOrWhiteSpace(f.Cve) ? "-" : f.Cve),
                    CsvEscape(SafeZhRisk(f.Risk)),
                    CsvEscape(f.Cvss?.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) ?? "N/A"),
                    CsvEscape($"{f.Description}; {f.VerificationDetail}"),
                    CsvEscape(f.Fix),
                    CsvEscape(f.Source)));
        if (IsConclusive(r) && r.VulnInfo?.Findings is not { Count: > 0 })
            sb.AppendLine($"{CsvEscape("漏洞")},,,,,,,,{CsvEscape("无漏洞")},,");
        else if (!IsConclusive(r) && r.VulnInfo?.Findings is not { Count: > 0 })
            sb.AppendLine($"{CsvEscape("漏洞")},,,,,,,,{CsvEscape("未执行或未完成漏洞扫描，不能得出安全结论")},,");
        return sb.ToString();
    }
    private static string CsvEscape(string s)
    {
        var value = s ?? "";
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    // ==================== MARKDOWN ====================
    private static string ToMarkdown(ScanReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# 🌫️ {MdEscape(r.Title)}\n> {MdEscape(r.Target)} · {r.GeneratedAt:yyyy-MM-dd HH:mm} · {MdEscape(r.ScanDuration)}\n");
        sb.AppendLine($"> {StatusEmoji(r)} **扫描状态：{MdEscape(StatusLabel(r))}** — {MdEscape(r.StatusMessage)}\n");
        sb.AppendLine("## 🧭 扫描范围\n");
        sb.AppendLine($"- 目标发现：{MdEscape(r.Scope.Discovery)}");
        sb.AppendLine($"- TCP 端口：{MdEscape(r.Scope.TcpPorts)}");
        sb.AppendLine($"- 漏洞检测：{MdEscape(r.Scope.VulnerabilityChecks)}");
        sb.AppendLine($"- 能力边界：{MdEscape(r.Scope.Limitations)}\n");
        if (r.Warnings.Count > 0)
        {
            sb.AppendLine("## ⚠️ 结果完整性\n");
            foreach (var warning in r.Warnings) sb.AppendLine($"- {MdEscape(warning)}");
            sb.AppendLine();
        }
        if (r.Notes.Count > 0)
        {
            sb.AppendLine("## ℹ️ 补充说明\n");
            foreach (var note in r.Notes) sb.AppendLine($"- {MdEscape(note)}");
            sb.AppendLine();
        }

        sb.AppendLine("## 🌐 网络暴露\n");
        if (!IsConclusive(r) && r.OpenPorts.Count == 0)
        {
            sb.AppendLine("未执行或未完成端口扫描，不能据此认为没有开放端口。\n");
        }
        else if (r.OpenPorts.Count == 0)
        {
            sb.AppendLine("未发现开放端口。\n");
        }
        else
        {
            sb.AppendLine("| 目标 | 端口 | 服务 | 状态 | 建议 |");
            sb.AppendLine("|------|------|------|------|------|");
            foreach (var port in r.OpenPorts)
                sb.AppendLine($"| {MdEscape(port.Target)} | `{port.Port}` | {MdEscape(port.Service)} | {MdEscape(port.State)} | {MdEscape(PortAdvice(port))} |");
            sb.AppendLine();
        }

        AppendSslMarkdown(sb, r.SslInfo);

        // 层1: 摘要
        sb.AppendLine("## 📊 紧急摘要");
        var v = r.VulnInfo;
        sb.AppendLine($"| 🔴 严重 | 🟡 高危 | 🟢 中危 | ⚪ 低危 | 总计 |");
        sb.AppendLine($"|---------|---------|---------|---------|------|");
        sb.AppendLine($"| {v?.CriticalCount ?? 0} | {v?.HighCount ?? 0} | {v?.MediumCount ?? 0} | {v?.LowCount ?? 0} | {v?.Findings.Count ?? 0} |\n");

        // 层2: 紧急漏洞详情
        if (v?.Findings is { Count: > 0 })
        {
            var urgent = v.Findings.Where(f => NormalizeRisk(f.Risk) is "critical" or "high").ToList();
            if (urgent.Count > 0)
            {
                sb.AppendLine("## 🚨 严重 + 高危漏洞\n");
                foreach (var f in urgent)
                    sb.AppendLine($"### {RiskEmoji(f.Risk)} {MdEscape(FindingTitle(f))}\n- 目标: `{MdEscape(f.Target)}` · 端口: `{f.Port}` · 服务: {MdEscape(f.Service)}\n- 评分: {MdEscape(ScoreLabel(f))} · 置信度: {MdEscape(ConfidenceLabel(f))} · 来源: {MdEscape(f.Source)}\n- 修复: {MdEscape(f.Fix)}\n");
            }

            // 层3: 完整表格
            sb.AppendLine("## 📋 完整漏洞列表\n");
            sb.AppendLine("| 目标 | CVE | 端口/服务 | 风险/CVSS | 置信度 | 来源 | 说明 | 修复建议 |");
            sb.AppendLine("|------|-----|-----------|-----------|--------|------|------|----------|");
            foreach (var f in v.Findings)
                sb.AppendLine($"| {MdEscape(f.Target)} | {MdEscape(string.IsNullOrWhiteSpace(f.Cve) ? "-" : f.Cve)} | `{f.Port}` {MdEscape(f.Service)} | {RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)} / {MdEscape(ScoreLabel(f))} | {MdEscape(ConfidenceLabel(f))} | {MdEscape(f.Source)} | {MdEscape($"{f.Description} {f.VerificationDetail}")} | {MdEscape(f.Fix)} |");

            // 层4: 修复建议
            var fixes = v.Findings.Where(f => !string.IsNullOrEmpty(f.Fix)).GroupBy(f => f.Fix!).Take(8);
            if (fixes.Any())
            {
                sb.AppendLine("\n## 🛠️ 修复建议 (按风险排序)\n");
                foreach (var g in fixes) sb.AppendLine($"- {MdEscape(g.Key)}");
            }
        }
        else if (IsConclusive(r))
        {
            sb.AppendLine("## 📋 漏洞详情\n\n✅ 在上述扫描范围内未发现漏洞候选项。\n");
        }
        else
        {
            sb.AppendLine("## 📋 漏洞详情\n\n⚠️ 未执行或未完成漏洞扫描，不能得出“未发现漏洞”结论。\n");
        }

        sb.AppendLine($"\n---\n*LucentMist v{LucentMist.Core.AppVersion.Current} · {r.GeneratedAt:yyyy-MM-dd HH:mm}*");
        return sb.ToString();
    }

    // ==================== HTML (Cyberpunk Theme) ====================
    private static string ToHtml(ScanReport r)
    {
        var v = r.VulnInfo;
        var statusClass = NormalizeStatus(r.ScanStatus);
        var warningItems = r.Warnings.Count == 0
            ? ""
            : $"<ul>{string.Join("", r.Warnings.Select(w => $"<li>{E(w)}</li>"))}</ul>";
        var noteItems = r.Notes.Count == 0
            ? ""
            : $"<div class='scan-notes'><strong>补充说明：</strong><ul>{string.Join("", r.Notes.Select(note => $"<li>{E(note)}</li>"))}</ul></div>";
        var statusBanner = $@"<div class='scan-status status-{statusClass}'>
  <div class='status-title'>{StatusEmoji(r)} 扫描状态：{E(StatusLabel(r))}</div>
  <div>{E(r.StatusMessage)}</div>{warningItems}{noteItems}
</div>";
        var scope = $@"<div class='section scope'><h2>🧭 扫描范围与边界</h2>
<ul><li><strong>目标发现：</strong>{E(r.Scope.Discovery)}</li>
<li><strong>TCP 端口：</strong>{E(r.Scope.TcpPorts)}</li>
<li><strong>漏洞检测：</strong>{E(r.Scope.VulnerabilityChecks)}</li>
<li><strong>能力边界：</strong>{E(r.Scope.Limitations)}</li></ul></div>";
        var overallRisk = NormalizeRisk(v?.OverallRisk ?? "");
        var riskBg = overallRisk switch
        {
            "critical" => "#7f1d1d",
            "high" => "#991b1b",
            "medium" => "#9a3412",
            _ => "#166534"
        };
        var riskGlow = overallRisk switch
        {
            "critical" => "#ef4444",
            "high" => "#f87171",
            "medium" => "#fb923c",
            _ => "#4ade80"
        };
        // 层1: 摘要
        var summary = $@"
<div class='urgent-summary'>
  <div class='sum-card severe'><div class='val'>{v?.CriticalCount ?? 0}</div><div class='lbl'>🔴 严重</div></div>
  <div class='sum-card high'><div class='val'>{v?.HighCount ?? 0}</div><div class='lbl'>🟡 高危</div></div>
  <div class='sum-card medium'><div class='val'>{v?.MediumCount ?? 0}</div><div class='lbl'>🟢 中危</div></div>
  <div class='sum-card low'><div class='val'>{v?.LowCount ?? 0}</div><div class='lbl'>⚪ 低危</div></div>
  <div class='sum-card total'><div class='val'>{v?.Findings.Count ?? 0}</div><div class='lbl'>📊 相关</div></div>
</div>";

        // 层2: 紧急漏洞
        var urgentHtml = "";
        if (v?.Findings is { Count: > 0 })
        {
            var urgent = v.Findings.Where(f => NormalizeRisk(f.Risk) is "critical" or "high").ToList();
            if (urgent.Count > 0)
            {
                urgentHtml = "<div class='section'><h2>🚨 紧急漏洞</h2><div class='urgent-grid'>";
                foreach (var f in urgent)
                    urgentHtml += $@"<div class='urgent-card {NormalizeRisk(f.Risk)}'>
                      <div class='urgent-badge'>{RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)}</div>
                      <div class='urgent-title'>{MakeLinksClickable(E(FindingTitle(f)))}</div>
                      <div class='urgent-meta'>目标 <code>{E(f.Target)}</code> · 端口 <code>{f.Port}</code> · {E(f.Service)}</div>
                      <div class='urgent-meta'>{E(ScoreLabel(f))} · {E(ConfidenceLabel(f))} · {E(f.Source)}</div>
                      <div class='urgent-fix'>{E(SmartFix(f.Risk, f.Fix))}</div>
                    </div>";
                urgentHtml += "</div></div>";
            }
        }

        // 层3: 分层表格（严重/高危展开，中危/低危折叠）
        var tableSection = "";
        if (v?.Findings is { Count: > 0 })
        {
            var criticalHigh = v.Findings.Where(f => NormalizeRisk(f.Risk) is "critical" or "high").ToList();
            var mediumLow = v.Findings.Where(f => NormalizeRisk(f.Risk) is "medium" or "low").ToList();
            tableSection += "<div class='section'><h2>📋 漏洞详情</h2>";
            if (criticalHigh.Count > 0)
                tableSection += $"<details open><summary>🔴🟡 严重 + 高危漏洞 ({criticalHigh.Count})</summary>{MakeTable(criticalHigh)}</details>";
            if (mediumLow.Count > 0)
                tableSection += $"<details><summary>🟢⚪ 中危 + 低危漏洞 ({mediumLow.Count})</summary>{MakeTable(mediumLow)}</details>";
            tableSection += "</div>";
        }
        else if (IsConclusive(r))
        {
            tableSection = "<div class='section'><h2>📋 漏洞详情</h2><div class='safe-msg'>✅ 在已披露的扫描范围内未发现漏洞候选项</div></div>";
        }
        else
        {
            tableSection = "<div class='section'><h2>📋 漏洞详情</h2><div class='incomplete-msg'>⚠️ 未执行或未完成漏洞扫描，不能得出安全结论</div></div>";
        }

        // 层4: 修复建议（仅严重/高危）
        var fixList = "";
        if (v?.Findings != null)
        {
            var fixes = v.Findings.Where(f => !string.IsNullOrEmpty(f.Fix) && NormalizeRisk(f.Risk) is "critical" or "high")
                .Select(f => SmartFix(f.Risk, f.Fix)).Distinct().Take(5).ToList();
            if (fixes.Count > 0)
            {
                fixList = "<div class='section'><h2>🛠️ 优先修复操作</h2><div class='fix-list'>";
                foreach (var g in fixes) fixList += $"<div class='fix-item'>{E(g)}</div>";
                fixList += "</div></div>";
            }
        }

        return $@"<!DOCTYPE html><html lang='zh-CN'>
<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{E(r.Title)}</title>
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0e17;--surface:#111827;--surface2:#1a2236;--text:#e2e8f0;--muted:#64748b;--cyan:#2dd4bf;--cyan-glow:rgba(45,212,191,.15)}}
body{{font-family:system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;
  background-image:radial-gradient(ellipse at 20% 0%,rgba(45,212,191,.06) 0%,transparent 60%),
                    radial-gradient(ellipse at 80% 100%,rgba(99,102,241,.04) 0%,transparent 60%),
                    linear-gradient(180deg,#0a0e17 0%,#0f172a 100%)}}
.container{{max-width:1024px;margin:0 auto;padding:2rem 1.5rem}}
header{{text-align:center;padding:3rem 0 2rem;position:relative}}
header::after{{content:'';position:absolute;bottom:0;left:25%;right:25%;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),transparent)}}
h1{{font-size:2.2rem;font-weight:900;background:linear-gradient(135deg,#2dd4bf 0%,#818cf8 50%,#2dd4bf 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:.5rem;letter-spacing:-.03em}}
.meta{{color:var(--muted);font-size:.85rem;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}}
.stat-card{{background:var(--surface);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:1.2rem;text-align:center;transition:all .2s}}
.stat-card:hover{{transform:translateY(-2px);border-color:rgba(45,212,191,.2);box-shadow:0 4px 20px rgba(0,0,0,.3)}}
.stat-card .val{{font-size:1.8rem;font-weight:900;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.stat-card .lbl{{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-top:.3rem}}
.stat-card.devices .val{{color:#818cf8}}.stat-card.online .val{{color:#4ade80}}.stat-card.ports .val{{color:#2dd4bf}}.stat-card.risk .val{{color:{riskGlow}}}

.urgent-summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin:1.5rem 0 2rem}}
.sum-card{{background:var(--surface);border:1px solid rgba(255,255,255,.05);border-radius:10px;padding:1rem;text-align:center}}
.sum-card .val{{font-size:1.5rem;font-weight:900;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.sum-card .lbl{{font-size:.7rem;margin-top:.2rem}}
.sum-card.severe .val{{color:#ef4444}}.sum-card.high .val{{color:#f87171}}.sum-card.medium .val{{color:#fbbf24}}.sum-card.low .val{{color:var(--muted)}}.sum-card.total .val{{color:var(--cyan)}}

.section{{margin:2rem 0}}
.section h2{{font-size:1.2rem;font-weight:700;color:var(--text);margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}}
.section h2::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(255,255,255,.1),transparent)}}
.urgent-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.8rem}}
.urgent-card{{background:var(--surface);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:1rem;border-left:3px solid}}
.urgent-card.critical{{border-left-color:#ef4444;background:linear-gradient(135deg,rgba(239,68,68,.08),var(--surface))}}
.urgent-card.high{{border-left-color:#f87171;background:linear-gradient(135deg,rgba(248,113,113,.05),var(--surface))}}
.urgent-badge{{font-size:.75rem;font-weight:700;margin-bottom:.4rem}}
.urgent-title{{font-weight:600;margin-bottom:.3rem}}
.urgent-meta{{font-size:.8rem;color:var(--muted);margin-bottom:.3rem}}
.urgent-fix{{font-size:.8rem;color:#4ade80}}

table{{width:100%;border-collapse:collapse;margin:.8rem 0 1.5rem;font-size:.84rem}}
th{{background:var(--surface2);color:var(--muted);padding:.6rem .8rem;text-align:left;font-weight:600;text-transform:uppercase;font-size:.7rem;letter-spacing:.05em}}
td{{padding:.55rem .8rem;border-bottom:1px solid rgba(255,255,255,.04)}}
tr.row-critical td{{background:rgba(239,68,68,.06)}}
tr.row-high td{{background:rgba(248,113,113,.03)}}
tr:hover td{{background:rgba(45,212,191,.04)!important}}
code{{background:var(--surface2);padding:.1rem .4rem;border-radius:3px;font-size:.8rem;color:var(--cyan)}}
.badge{{display:inline-flex;align-items:center;gap:.3rem;padding:.15rem .55rem;border-radius:5px;font-size:.72rem;font-weight:700}}
.badge-critical{{background:rgba(239,68,68,.15);color:#ef4444}}
.badge-high{{background:rgba(248,113,113,.12);color:#f87171}}
.badge-medium{{background:rgba(251,191,36,.12);color:#fbbf24}}
.badge-low{{background:rgba(148,163,184,.1);color:#94a3b8}}
.fix-cell{{font-size:.78rem;color:#94a3b8;max-width:250px}}
.safe-msg{{color:#4ade80;text-align:center;padding:2rem}}
.incomplete-msg{{color:#fbbf24;text-align:center;padding:2rem;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.22);border-radius:10px}}
.scan-status{{margin:1.5rem 0;padding:1rem 1.2rem;border-radius:10px;border:1px solid;font-size:.88rem}}.scan-status ul{{margin:.6rem 0 0 1.2rem}}.scan-notes{{margin-top:.7rem;color:#cbd5e1}}.status-title{{font-weight:800;margin-bottom:.25rem}}.status-completed{{color:#4ade80;background:rgba(74,222,128,.08);border-color:rgba(74,222,128,.25)}}.status-partial,.status-no_targets,.status-not_scanned,.status-running{{color:#fbbf24;background:rgba(251,191,36,.08);border-color:rgba(251,191,36,.25)}}.status-failed{{color:#f87171;background:rgba(248,113,113,.08);border-color:rgba(248,113,113,.25)}}
.scope ul{{margin-left:1.2rem;display:grid;gap:.45rem;color:#94a3b8}}.scope strong{{color:var(--text)}}
.tls-status{{font-weight:700}}.tls-valid{{color:#4ade80}}.tls-warning{{color:#fbbf24}}.tls-expired{{color:#ef4444}}
.fix-list{{display:flex;flex-direction:column;gap:.5rem}}
.fix-item{{background:var(--surface);border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:.8rem 1rem;font-size:.84rem;border-left:3px solid var(--cyan)}}
.fix-item::before{{content:'🔧 '}}
footer{{text-align:center;padding:2rem 0;color:var(--muted);font-size:.75rem;border-top:1px solid rgba(255,255,255,.04);margin-top:3rem}}
details{{margin:.4rem 0}}details summary{{cursor:pointer;padding:.6rem .8rem;background:var(--surface2);border-radius:8px;font-weight:600;font-size:.85rem;user-select:none;list-style:none}}details summary::before{{content:'▶ ';font-size:.7rem;margin-right:.4rem}}details[open] summary::before{{content:'▼ '}}details[open] summary{{border-radius:8px 8px 0 0}}details table{{margin-top:0}}details[open] table{{margin-top:0}}.nvd-link{{color:var(--cyan);text-decoration:none;word-break:break-all;font-size:.78rem}}.nvd-link:hover{{text-decoration:underline;color:#5ee8d4}}@media(max-width:768px){{.stats,.urgent-summary{{grid-template-columns:repeat(2,1fr)}}.urgent-grid{{grid-template-columns:1fr}}h1{{font-size:1.5rem}}}}
</style></head><body><div class='container'>
<header><h1>🌫️ {E(r.Title)}</h1><p class='meta'>{E(r.Target)} · {r.GeneratedAt:yyyy-MM-dd HH:mm:ss} · 耗时 {E(r.ScanDuration)}</p></header>
{statusBanner}
{scope}
<div class='stats'>
  <div class='stat-card devices'><div class='val'>{r.TotalDevices}</div><div class='lbl'>总设备</div></div>
  <div class='stat-card online'><div class='val'>{r.OnlineDevices}</div><div class='lbl'>在线</div></div>
  <div class='stat-card ports'><div class='val'>{r.OpenPorts.Count}</div><div class='lbl'>开放端口</div></div>
  <div class='stat-card risk'><div class='val'>{E(v?.OverallRisk ?? "-")}</div><div class='lbl'>综合风险</div></div>
</div>
{OpenPortsTable(r)}
{SslTable(r)}
{summary}
{urgentHtml}
{tableSection}
{DeviceTable(r)}
{fixList}
<footer>LucentMist v{LucentMist.Core.AppVersion.Current} · {r.GeneratedAt:yyyy-MM-dd HH:mm:ss} · AI-Powered Network Security Scanner</footer>
</div></body></html>";
    }

    private static string MakeTable(List<VulnFinding> list) =>
        "<table><thead><tr><th>目标</th><th>CVE</th><th>端口/服务</th><th>风险/CVSS</th><th>置信度</th><th>来源</th><th>说明</th><th>修复建议</th></tr></thead><tbody>" +
        string.Join("", list.Select(f =>
            $"<tr class='row-{NormalizeRisk(f.Risk)}'><td><code>{E(f.Target)}</code></td><td>{E(string.IsNullOrWhiteSpace(f.Cve) ? "-" : f.Cve)}</td><td><code>{f.Port}</code> {E(f.Service)}</td><td><span class='badge badge-{NormalizeRisk(f.Risk)}'>{RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)}</span><br>{E(ScoreLabel(f))}</td><td>{E(ConfidenceLabel(f))}</td><td>{E(f.Source)}</td><td>{MakeLinksClickable(E($"{f.Description} {f.VerificationDetail}"))}</td><td class='fix-cell'>{E(SmartFix(f.Risk, f.Fix))}</td></tr>")) +
        "</tbody></table>";

    private static string MakeLinksClickable(string text) =>
        System.Text.RegularExpressions.Regex.Replace(text ?? "",
            @"(https?://[^\s<>""']+)",
            "<a href='$1' target='_blank' class='nvd-link'>$1</a>");

    private static string DeviceTable(ScanReport r)
    {
        if (r.Devices.Count == 0) return "";
        var rows = string.Join("", r.Devices.Select(d =>
            $"<tr><td>{E(d.Ip)}</td><td>{(d.IsAlive ? "✅ 在线" : "离线")}</td><td>{E(d.OsGuess)}</td></tr>"));
        return $"<div class='section'><h2>🖥️ 设备清单</h2><table><thead><tr><th>IP</th><th>状态</th><th>OS</th></tr></thead><tbody>{rows}</tbody></table></div>";
    }

    private static string OpenPortsTable(ScanReport r)
    {
        if (r.OpenPorts.Count == 0) return "";
        var rows = string.Join("", r.OpenPorts.Select(port =>
            $"<tr><td>{E(port.Target)}</td><td><code>{port.Port}</code></td><td>{E(port.Service)}</td><td>{E(port.State)}</td><td class='fix-cell'>{E(PortAdvice(port))}</td></tr>"));
        return $"<div class='section'><h2>🌐 网络暴露</h2><table><thead><tr><th>目标</th><th>端口</th><th>服务</th><th>状态</th><th>建议</th></tr></thead><tbody>{rows}</tbody></table></div>";
    }

    private static string SslTable(ScanReport r)
    {
        if (r.SslInfo.Count == 0) return "";
        var rows = string.Join("", r.SslInfo.Select(ssl =>
        {
            var (label, css) = SslStatus(ssl);
            return $"<tr><td>{E(ssl.Target)}</td><td><code>{ssl.Port}</code></td><td>{E(ssl.Subject)}</td><td>{E(ssl.Issuer)}</td><td>{E(ssl.NotAfter)}</td><td class='tls-status {css}'>{E(label)}</td></tr>";
        }));
        return $"<div class='section'><h2>🔐 TLS 证书</h2><table><thead><tr><th>目标</th><th>端口</th><th>证书主体</th><th>签发者</th><th>到期时间</th><th>状态</th></tr></thead><tbody>{rows}</tbody></table></div>";
    }

    private static void AppendSslMarkdown(StringBuilder sb, List<SslEntry> entries)
    {
        if (entries.Count == 0) return;

        sb.AppendLine("## 🔐 TLS 证书\n");
        sb.AppendLine("| 目标 | 端口 | 证书主体 | 签发者 | 到期时间 | 状态 |");
        sb.AppendLine("|------|------|----------|--------|----------|------|");
        foreach (var ssl in entries)
        {
            var (label, _) = SslStatus(ssl);
            sb.AppendLine($"| {MdEscape(ssl.Target)} | `{ssl.Port}` | {MdEscape(ssl.Subject)} | {MdEscape(ssl.Issuer)} | {MdEscape(ssl.NotAfter)} | {MdEscape(label)} |");
        }
        sb.AppendLine();
    }

    private static (string Label, string Css) SslStatus(SslEntry ssl)
    {
        var validity = ssl.IsExpired
            ? "❌ 已过期"
            : ssl.DaysRemaining <= 30
                ? $"⚠️ {ssl.DaysRemaining} 天后到期"
                : $"✅ 有效期内（剩余 {ssl.DaysRemaining} 天）";
        if (ssl.TrustErrors.Count > 0)
            return ($"{validity}；信任错误: {TrustErrorLabel(ssl)}", ssl.IsExpired ? "tls-expired" : "tls-warning");
        return (validity, ssl.IsExpired ? "tls-expired" : ssl.DaysRemaining <= 30 ? "tls-warning" : "tls-valid");
    }

    private static string TrustErrorLabel(SslEntry ssl) =>
        ssl.TrustErrors.Count == 0
            ? "无"
            : string.Join(", ", ssl.TrustErrors.Select(error => error switch
            {
                "UntrustedRoot" => "不可信根或自签证书 (UntrustedRoot)",
                "NameMismatch" => "主机名不匹配 (NameMismatch)",
                "NotTimeValid" => "证书不在有效期内 (NotTimeValid)",
                "RevocationStatusUnknown" => "无法确认吊销状态 (RevocationStatusUnknown)",
                "PartialChain" => "证书链不完整 (PartialChain)",
                "ChainErrors" => "证书链验证失败 (ChainErrors)",
                _ => error
            }));

    private static string SslAdvice(SslEntry ssl)
    {
        if (ssl.IsExpired || ssl.DaysRemaining <= 30)
            return ssl.TrustErrors.Count > 0
                ? "更换为与主机名匹配且由受信任 CA 签发的证书，并检查续期"
                : "尽快更换或续期证书";
        return ssl.TrustErrors.Count > 0
            ? "更换为与主机名匹配且由受信任 CA 签发的证书"
            : "保持自动续期并定期检查";
    }

    private static string PortAdvice(PortEntry port) => port.Port switch
    {
        21 or 23 or 80 or 110 or 143 => "明文协议；如非必需请关闭，或改用加密协议",
        22 or 3389 => "管理入口；限制来源 IP，启用强认证和登录审计",
        445 => "文件共享；不应暴露到互联网，限制在受信网络内",
        2375 or 3306 or 5432 or 6379 or 9200 or 27017 => "高价值后端服务；使用防火墙限制访问并启用认证",
        _ => "确认业务必要性，并仅允许受信来源访问"
    };

    private static bool IsConclusive(ScanReport report) =>
        NormalizeStatus(report.ScanStatus) == "completed";

    private static string NormalizeStatus(string status) =>
        (status ?? "").Trim().ToLowerInvariant() switch
        {
            "completed" => "completed",
            "partial" => "partial",
            "no_targets" => "no_targets",
            "failed" => "failed",
            "running" => "running",
            _ => "not_scanned"
        };

    private static string StatusLabel(ScanReport report) => NormalizeStatus(report.ScanStatus) switch
    {
        "completed" => "已完成",
        "partial" => "部分完成，结果不完整",
        "no_targets" => "未发现在线设备",
        "failed" => "扫描失败",
        "running" => "扫描中",
        _ => "未执行"
    };

    private static string StatusEmoji(ScanReport report) => NormalizeStatus(report.ScanStatus) switch
    {
        "completed" => "✅",
        "failed" => "❌",
        _ => "⚠️"
    };

    private static string FindingTitle(VulnFinding finding) =>
        string.IsNullOrWhiteSpace(finding.Cve)
            ? finding.Description
            : $"{finding.Cve} — {finding.Description}";

    private static string ScoreLabel(VulnFinding finding) =>
        finding.Cvss is { } score
            ? $"CVSS {score.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)}"
            : "CVSS N/A";

    private static string ConfidenceLabel(VulnFinding finding) =>
        finding.Confirmed ? "✔ 已验证" : "⚠ 候选";

    private static string NormalizeRisk(string risk) =>
        (risk ?? "").Trim().ToLowerInvariant() switch
        {
            "critical" or "\u4e25\u91cd" => "critical",
            "high" or "\u9ad8\u5371" => "high",
            "medium" or "\u4e2d\u5371" or "\u4e2d" => "medium",
            "low" or "\u4f4e\u5371" or "\u4f4e" => "low",
            _ => "low"
        };

    private static string SafeZhRisk(string risk) =>
        NormalizeRisk(risk) switch
        {
            "critical" => "\u4e25\u91cd",
            "high" => "\u9ad8\u5371",
            "medium" => "\u4e2d\u5371",
            _ => "\u4f4e\u5371"
        };

    private static string SmartFix(string risk, string existingFix)
    {
        var normalized = NormalizeRisk(risk);
        return normalized switch
        {
            "critical" or "high" => !string.IsNullOrEmpty(existingFix) && !existingFix.StartsWith("参考") ? $"🔧 {existingFix}" : "🔧 立即安装最新补丁，禁用受影响服务",
            "medium" => !string.IsNullOrEmpty(existingFix) && !existingFix.StartsWith("参考") ? $"{existingFix}" : "建议升级到最新版本或限制访问",
            _ => "一般参考信息，无需紧急处理"
        };
    }

    private static string MdEscape(string s) =>
        (s ?? "")
            .Replace("\\", "\\\\")
            .Replace("`", "\\`")
            .Replace("|", "\\|")
            .Replace("\r", " ")
            .Replace("\n", " ");

    private static string RiskEmoji(string r) => NormalizeRisk(r) switch
    {
        "critical" => "🔴",
        "high" => "🟡",
        "medium" => "🟢",
        _ => "⚪"
    };
    private static string ZhRisk(string r) => r switch { "critical" => "严重", "high" => "高危", "medium" => "中危", "low" => "低危", "严重" or "高危" or "中危" or "低危" => r, _ => r };
    private static string E(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");
}
