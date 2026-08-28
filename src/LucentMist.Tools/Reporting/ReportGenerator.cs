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
        public List<DeviceEntry> Devices { get; set; } = new();
        public List<PortEntry> OpenPorts { get; set; } = new();
        public SslEntry? SslInfo { get; set; }
        public VulnSummary? VulnInfo { get; set; }
    }
    public class DeviceEntry { public string Ip { get; set; } = ""; public bool IsAlive { get; set; } public string OsGuess { get; set; } = ""; }
    public class PortEntry { public string Target { get; set; } = ""; public int Port { get; set; } public string Service { get; set; } = ""; public string State { get; set; } = "open"; }
    public class SslEntry { public string Target { get; set; } = ""; public int Port { get; set; } public string Subject { get; set; } = ""; public string Issuer { get; set; } = ""; public string NotAfter { get; set; } = ""; public int DaysRemaining { get; set; } public bool IsExpired { get; set; } }
    public class VulnSummary { public string OverallRisk { get; set; } = "安全"; public int CriticalCount { get; set; } public int HighCount { get; set; } public int MediumCount { get; set; } public int LowCount { get; set; } public List<VulnFinding> Findings { get; set; } = new(); }
    public class VulnFinding { public int Port { get; set; } public string Service { get; set; } = ""; public string Risk { get; set; } = ""; public string Description { get; set; } = ""; public string Fix { get; set; } = ""; }

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
        sb.AppendLine("端口,服务,CVE,风险,CVSS,描述,修复建议,来源");
        if (r.VulnInfo?.Findings != null)
            foreach (var f in r.VulnInfo.Findings)
                sb.AppendLine($"{f.Port},{CsvEscape(f.Service)},{CsvEscape("-")},{SafeZhRisk(f.Risk)},{CsvEscape("-")},{CsvEscape(f.Description)},{CsvEscape(f.Fix)},{CsvEscape("-")}");
        if (r.VulnInfo?.Findings is not { Count: > 0 })
            sb.AppendLine("无漏洞,,,,,,");
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

        // 层1: 摘要
        sb.AppendLine("## 📊 紧急摘要");
        var v = r.VulnInfo;
        sb.AppendLine($"| 🔴 严重 | 🟡 高危 | 🟢 中危 | ⚪ 低危 | 总计 |");
        sb.AppendLine($"|---------|---------|---------|---------|------|");
        sb.AppendLine($"| {v?.CriticalCount ?? 0} | {v?.HighCount ?? 0} | {v?.MediumCount ?? 0} | {v?.LowCount ?? 0} | {v?.Findings.Count ?? 0} |\n");

        // 层2: 紧急漏洞详情
        if (v?.Findings != null)
        {
            var urgent = v.Findings.Where(f => NormalizeRisk(f.Risk) is "critical" or "high").ToList();
            if (urgent.Count > 0)
            {
                sb.AppendLine("## 🚨 严重 + 高危漏洞\n");
                foreach (var f in urgent)
                    sb.AppendLine($"### {RiskEmoji(f.Risk)} {MdEscape(f.Description)}\n- 端口: `{f.Port}` · 服务: {MdEscape(f.Service)}\n- 修复: {MdEscape(f.Fix)}\n");
            }

            // 层3: 完整表格
            sb.AppendLine("## 📋 完整漏洞列表\n");
            sb.AppendLine("| 端口 | 服务 | 风险 | 说明 | 修复建议 |");
            sb.AppendLine("|------|------|------|------|----------|");
            foreach (var f in v.Findings)
                sb.AppendLine($"| {f.Port} | {MdEscape(f.Service)} | {RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)} | {MdEscape(f.Description)} | {MdEscape(f.Fix)} |");

            // 层4: 修复建议
            var fixes = v.Findings.Where(f => !string.IsNullOrEmpty(f.Fix)).GroupBy(f => f.Fix!).Take(8);
            if (fixes.Any())
            {
                sb.AppendLine("\n## 🛠️ 修复建议 (按风险排序)\n");
                foreach (var g in fixes) sb.AppendLine($"- {MdEscape(g.Key)}");
            }
        }

        sb.AppendLine($"\n---\n*LucentMist v{LucentMist.Core.AppVersion.Current} · {r.GeneratedAt:yyyy-MM-dd HH:mm}*");
        return sb.ToString();
    }

    // ==================== HTML (Cyberpunk Theme) ====================
    private static string ToHtml(ScanReport r)
    {
        var v = r.VulnInfo;
        var osGuess = r.Devices.FirstOrDefault()?.OsGuess ?? "";
        var filteredCount = v?.Findings != null ? FilterAndCount(v.Findings, osGuess) : 0;
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
        var filterNote = filteredCount > 0 ? $"<div class='filter-note'>🔍 已过滤 {filteredCount} 个历史漏洞（与当前 OS 无关）</div>" : "";

        // 层1: 摘要
        var summary = $@"
<div class='urgent-summary'>
  <div class='sum-card severe'><div class='val'>{v?.CriticalCount ?? 0}</div><div class='lbl'>🔴 严重</div></div>
  <div class='sum-card high'><div class='val'>{v?.HighCount ?? 0}</div><div class='lbl'>🟡 高危</div></div>
  <div class='sum-card medium'><div class='val'>{v?.MediumCount ?? 0}</div><div class='lbl'>🟢 中危</div></div>
  <div class='sum-card low'><div class='val'>{v?.LowCount ?? 0}</div><div class='lbl'>⚪ 低危</div></div>
  <div class='sum-card total'><div class='val'>{v?.Findings.Count ?? 0}</div><div class='lbl'>📊 相关</div></div>
</div>{filterNote}";

        // 层2: 紧急漏洞
        var urgentHtml = "";
        if (v?.Findings != null)
        {
            var urgent = v.Findings.Where(f => NormalizeRisk(f.Risk) is "critical" or "high").ToList();
            if (urgent.Count > 0)
            {
                urgentHtml = "<div class='section'><h2>🚨 紧急漏洞</h2><div class='urgent-grid'>";
                foreach (var f in urgent)
                    urgentHtml += $@"<div class='urgent-card {NormalizeRisk(f.Risk)}'>
                      <div class='urgent-badge'>{RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)}</div>
                      <div class='urgent-title'>{MakeLinksClickable(E(f.Description))}</div>
                      <div class='urgent-meta'>端口 <code>{f.Port}</code> · {E(f.Service)}</div>
                      <div class='urgent-fix'>{E(SmartFix(f.Risk, f.Fix))}</div>
                    </div>";
                urgentHtml += "</div></div>";
            }
        }

        // 层3: 分层表格（严重/高危展开，中危/低危折叠）
        var tableSection = "";
        if (v?.Findings != null)
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
        else { tableSection = "<div class='section'><h2>📋 漏洞详情</h2><div class='safe-msg'>✅ 未发现漏洞</div></div>"; }

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
.fix-list{{display:flex;flex-direction:column;gap:.5rem}}
.fix-item{{background:var(--surface);border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:.8rem 1rem;font-size:.84rem;border-left:3px solid var(--cyan)}}
.fix-item::before{{content:'🔧 '}}
footer{{text-align:center;padding:2rem 0;color:var(--muted);font-size:.75rem;border-top:1px solid rgba(255,255,255,.04);margin-top:3rem}}
details{{margin:.4rem 0}}details summary{{cursor:pointer;padding:.6rem .8rem;background:var(--surface2);border-radius:8px;font-weight:600;font-size:.85rem;user-select:none;list-style:none}}details summary::before{{content:'▶ ';font-size:.7rem;margin-right:.4rem}}details[open] summary::before{{content:'▼ '}}details[open] summary{{border-radius:8px 8px 0 0}}details table{{margin-top:0}}details[open] table{{margin-top:0}}.nvd-link{{color:var(--cyan);text-decoration:none;word-break:break-all;font-size:.78rem}}.nvd-link:hover{{text-decoration:underline;color:#5ee8d4}}.filter-note{{background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);border-radius:8px;padding:.6rem 1rem;font-size:.82rem;color:#fbbf24;margin-top:.5rem;text-align:center}}@media(max-width:768px){{.stats,.urgent-summary{{grid-template-columns:repeat(2,1fr)}}.urgent-grid{{grid-template-columns:1fr}}h1{{font-size:1.5rem}}}}
</style></head><body><div class='container'>
<header><h1>🌫️ {E(r.Title)}</h1><p class='meta'>{E(r.Target)} · {r.GeneratedAt:yyyy-MM-dd HH:mm:ss} · 耗时 {E(r.ScanDuration)}</p></header>
<div class='stats'>
  <div class='stat-card devices'><div class='val'>{r.TotalDevices}</div><div class='lbl'>总设备</div></div>
  <div class='stat-card online'><div class='val'>{r.OnlineDevices}</div><div class='lbl'>在线</div></div>
  <div class='stat-card ports'><div class='val'>{r.OpenPorts.Count}</div><div class='lbl'>开放端口</div></div>
  <div class='stat-card risk'><div class='val'>{E(v?.OverallRisk ?? "-")}</div><div class='lbl'>综合风险</div></div>
</div>
{summary}
{urgentHtml}
{tableSection}
{OpenPortsTable(r)}
{DeviceTable(r)}
{fixList}
<footer>LucentMist v{LucentMist.Core.AppVersion.Current} · {r.GeneratedAt:yyyy-MM-dd HH:mm:ss} · AI-Powered Network Security Scanner</footer>
</div></body></html>";
    }

    private static string MakeTable(List<VulnFinding> list) =>
        "<table><thead><tr><th>端口</th><th>服务</th><th>风险</th><th>说明</th><th>修复建议</th></tr></thead><tbody>" +
        string.Join("", list.Select(f =>
            $"<tr class='row-{NormalizeRisk(f.Risk)}'><td><code>{f.Port}</code></td><td>{E(f.Service)}</td><td><span class='badge badge-{NormalizeRisk(f.Risk)}'>{RiskEmoji(f.Risk)} {SafeZhRisk(f.Risk)}</span></td><td>{MakeLinksClickable(E(f.Description))}</td><td class='fix-cell'>{E(SmartFix(f.Risk, f.Fix))}</td></tr>")) +
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
            $"<tr><td><code>{port.Port}</code></td><td>{E(port.Service)}</td><td>{E(port.Target)}</td></tr>"));
        return $"<div class='section'><h2>🌐 开放端口</h2><table><thead><tr><th>端口</th><th>服务</th><th>目标</th></tr></thead><tbody>{rows}</tbody></table></div>";
    }

    private static int ExtractYear(string desc)
    {
        if (string.IsNullOrEmpty(desc)) return 0;
        // Try CVE-YEAR-NNNN pattern
        var m = System.Text.RegularExpressions.Regex.Match(desc, @"CVE-(\d{4})-\d+");
        if (m.Success) return int.Parse(m.Groups[1].Value);
        // Try a standalone year in description: "Windows 95", "SunOS 4.1.1", etc.
        m = System.Text.RegularExpressions.Regex.Match(desc, @"\b(19\d{2}|20\d{2})\b");
        return m.Success ? int.Parse(m.Groups[1].Value) : 0;
    }

    private static int OsThreshold(string os) => os switch
    {
        var x when x.Contains("Windows") && (x.Contains("10") || x.Contains("11")) => 2015,
        var x when x.Contains("Windows") => 2012,
        var x when x.Contains("macOS") || x.Contains("iOS") => 2015,
        var x when x.Contains("Android") => 2015,
        var x when x.Contains("Linux") => 2010,
        _ => 2010
    };

    private static int FilterAndCount(List<VulnFinding> findings, string osGuess)
    {
        if (string.IsNullOrEmpty(osGuess)) return 0;
        var threshold = OsThreshold(osGuess);
        return findings.Count(f => { var y = ExtractYear(f.Description); return y > 0 && y < threshold; });
    }

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
