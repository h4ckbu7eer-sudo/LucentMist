using System.Text.Json;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

/// <summary>
/// 内置 CVE 漏洞特征库
/// </summary>
public static class CveDatabase
{
    public record CveEntry(
        string Cve,
        string Name,
        int Port,
        string Service,
        string Risk,       // critical / high / medium / low
        string MatchBanner, // 包含检测，支持 "version < X.Y" 格式
        string DetectProbe, // 验证探测类型: smbv1 / smbv2 / http_version / openssh_version
        string Fix,
        bool CanMatchBanner = true,
        AffectedVersionRange[]? AffectedRanges = null,
        string? Conditions = null,
        string? Reference = null
    );

    private static readonly List<CveEntry> _entries = new()
    {
        new("CVE-2017-0144", "EternalBlue", 445, "SMB",
            "critical", "SMBv1", "smbv1",
            "安装 MS17-010 对应系统安全更新；禁用 SMBv1；限制 TCP 445 端口访问"),

        new("CVE-2020-0796", "SMBGhost", 445, "SMB",
            "critical", "SMBv3.1.1", "smbv3",
            "安装 KB4551762；若暂时无法打补丁，设置 LanmanServer\\Parameters\\DisableCompression=1 禁用 SMB 压缩；限制 TCP 445 端口访问",
            CanMatchBanner: false),

        new("CVE-2023-38408", "OpenSSH RCE", 22, "SSH",
            "high", "OpenSSH < 9.3p2", "openssh_version",
            "升级 OpenSSH 到 9.3p2+；限制 ssh-agent 转发和 PKCS#11 加载",
            AffectedRanges: [new("5.5", "9.3p2")],
            Conditions: "ssh-agent 转发及 PKCS#11 条件；sshd banner 不能证明客户端组件或发行版补丁状态",
            Reference: "https://www.openssh.com/txt/release-9.3p2"),

        new("CVE-2023-44487", "HTTP/2 Rapid Reset", 80, "HTTP",
            "high", "nginx < 1.25.3", "http_version",
            "应用厂商 HTTP/2 Rapid Reset 缓解更新并限制并发请求；检查 HTTP/2 配置",
            CanMatchBanner: false,
            Conditions: "仅 nginx 版本不能证明 HTTP/2 启用、流限制及缓解配置"),

        new("CVE-2024-21626", "runc Container Escape", 2375, "Docker",
            "high", "runc < 1.1.12", "runc_version",
            "升级 runc 到 1.1.12+；Docker Engine 升级到 24.0.9+ 或 25.0.2+",
            CanMatchBanner: false),

        new("CVE-2023-5157", "MariaDB/Galera DoS", 3306, "MariaDB",
            "high", "MariaDB distribution version", "mariadb_distribution_version",
            "按发行版安全公告升级 MariaDB/Galera，并限制数据库端口访问",
            CanMatchBanner: false),

        new("CVE-2019-0708", "BlueKeep", 3389, "RDP",
            "critical", "Windows RDP patch level", "windows_patch_level",
            "安装对应 Windows 安全更新并启用 NLA，或禁用远程桌面",
            CanMatchBanner: false),

        new("CVE-2022-0543", "Redis LUA RCE", 6379, "Redis",
            "critical", "Debian Redis package version", "debian_package_version",
            "安装 Debian Redis 安全更新，并启用认证和网络访问控制",
            CanMatchBanner: false),

        new("CVE-2021-44228", "Log4Shell", 8080, "HTTP",
            "critical", "Log4j Core version", "log4j_component_version",
            "按 Java 版本升级 Log4j Core 到官方修复版本并检查所有打包依赖",
            CanMatchBanner: false),

        new("CVE-2018-15473", "OpenSSH User Enum", 22, "SSH",
            "medium", "OpenSSH < 7.8", "openssh_version",
            "升级 OpenSSH 到 7.8+"),

        new("CVE-2024-6387", "OpenSSH regreSSHion", 22, "SSH", "critical", "OpenSSH < 9.8p1", "openssh_version",
            "升级到 OpenSSH 9.8p1+ 或安装发行版修复；核对平台及回补补丁",
            AffectedRanges: [new("8.5p1", "9.8p1")],
            Conditions: "Portable sshd 非 OpenBSD 平台；发行版可能已回补，不代表已证实 RCE",
            Reference: "https://www.openssh.com/txt/release-9.8"),
        new("CVE-2025-26466", "OpenSSH pre-auth DoS", 22, "SSH", "high", "OpenSSH < 9.9p2", "openssh_version",
            "升级 OpenSSH 9.9p2+ 或安装发行版修复；评估 PerSourcePenalties",
            AffectedRanges: [new("9.5p1", "9.9p2")],
            Conditions: "sshd SSH2_MSG_PING；需核对发行版补丁及限流",
            Reference: "https://www.openssh.com/security.html"),
        new("CVE-2021-41773", "Apache HTTP Server path traversal", 80, "HTTP", "high", "Apache < 2.4.50", "http_version",
            "升级 Apache httpd 2.4.51+；保持 Require all denied 并检查 Alias/CGI 配置",
            AffectedRanges: [new("2.4.49", "2.4.50")], Conditions: "Alias 路径权限配置影响；启用 CGI 才可能升级为 RCE",
            Reference: "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773"),
        new("CVE-2021-42013", "Apache HTTP Server incomplete traversal fix", 80, "HTTP", "critical", "Apache < 2.4.51", "http_version",
            "升级 Apache httpd 2.4.51+；检查 Alias 路径访问控制及 CGI",
            AffectedRanges: [new("2.4.49", "2.4.51")], Conditions: "需存在受影响 Alias 权限配置；未执行穿越或代码执行验证",
            Reference: "https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013"),
        new("CVE-2021-23017", "nginx resolver memory overwrite", 80, "HTTP", "medium", "nginx < 1.20.1", "http_version",
            "升级 nginx 1.20.1/1.21.0+；审查 resolver 配置及 DNS 网络信任",
            AffectedRanges: [new("0.6.18", "1.20.1")], Conditions: "需使用 resolver 且攻击者能伪造 DNS 响应",
            Reference: "https://nginx.org/en/security_advisories.html"),
        new("CVE-2024-24989", "nginx HTTP/3 null dereference", 80, "HTTP", "high", "nginx < 1.25.4", "http_version",
            "升级 nginx 1.25.4+；未升级前关闭 HTTP/3",
            AffectedRanges: [new("1.25.3", "1.25.4")], Conditions: "仅启用 HTTP/3 时适用；TCP banner 不证明 QUIC 配置",
            Reference: "https://nginx.org/en/security_advisories.html"),
        new("CVE-2024-24990", "nginx HTTP/3 use-after-free", 80, "HTTP", "high", "nginx < 1.25.4", "http_version",
            "升级 nginx 1.25.4+；未升级前关闭 HTTP/3",
            AffectedRanges: [new("1.25.0", "1.25.4")], Conditions: "仅启用 HTTP/3 时适用；未确认利用条件",
            Reference: "https://nginx.org/en/security_advisories.html"),
    };

    public static IReadOnlyList<CveEntry> Entries => _entries;

    static CveDatabase()
    {
        LoadExternalEntries();
    }

    public static CveEntry? FindByCve(string cveId) =>
        Entries.FirstOrDefault(e => e.Cve.Equals(cveId, StringComparison.OrdinalIgnoreCase));

    public static CveEntry[] Lookup(int port) =>
        Entries.Where(e => e.Port == port || (e.Service == "HTTP" && port is 80 or 443 or 8000 or 8080 or 8443 or 8888)).ToArray();

    public static CveEntry[] Match(int port, string? banner)
    {
        // banner 为空时不返回任何 CVE，防止"端口开放即漏洞"
        if (string.IsNullOrWhiteSpace(banner)) return [];
        var entries = Lookup(port);

        return entries.Where(e => e.CanMatchBanner && !string.IsNullOrWhiteSpace(e.MatchBanner)).Where(e =>
        {
            if (e.MatchBanner.Contains("<"))
            {
                // Version comparison: "OpenSSH < 9.0" → check banner version
                var parts = e.MatchBanner.Split('<');
                if (parts.Length != 2) return banner.Contains(e.MatchBanner, StringComparison.OrdinalIgnoreCase);
                var fingerprint = ServiceFingerprint.FromBanner(banner);
                if (fingerprint?.Version is not string ver ||
                    !fingerprint.ProductKey.Equals(parts[0].Trim(), StringComparison.OrdinalIgnoreCase)) return false;
                return e.AffectedRanges is { Length: > 0 }
                    ? e.AffectedRanges.Any(range => range.Contains(ver))
                    : AffectedVersionRange.Compare(ver, parts[1].Trim()) is < 0;
            }
            return banner.Contains(e.MatchBanner, StringComparison.OrdinalIgnoreCase);
        }).ToArray();
    }

    internal static bool HasVersionEvidence(int port, string? banner)
    {
        if (string.IsNullOrWhiteSpace(banner)) return false;

        if (port == 445)
        {
            return System.Text.RegularExpressions.Regex.IsMatch(
                banner,
                @"\bSMBv(?:1|2\.0\.2|2\.1|3\.0|3\.0\.2|3\.1\.1)\b",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        return ServiceFingerprint.FromBanner(banner)?.Version != null;
    }

    internal static string? ExtractVersion(string banner)
    {
        // Preserve the product's version spelling. In particular, OpenSSH's "p"
        // suffix is part of the upstream version and must not be rewritten before
        // sending it to a version-aware external source.
        // Extract version like: "OpenSSH_8.9p1" → "8.9p1"
        // "nginx/1.24.0" → "1.24.0"
        // "SMBv1" → "1.0.0"
        var smb = System.Text.RegularExpressions.Regex.Match(
            banner,
            @"\bSMBv(?<version>\d+(?:\.\d+)*)\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (smb.Success) return smb.Groups["version"].Value;

        // "SSH-2.0-OpenSSH_8.9p1" 必须取产品版本 8.9.1，而不是协议版本 2.0
        if (banner.Contains("OpenSSH_", StringComparison.OrdinalIgnoreCase))
        {
            var openssh = System.Text.RegularExpressions.Regex.Match(
                banner,
                @"OpenSSH[_-]?(?:for[_-]?Windows[_-]?)?(\d+(?:\.\d+)+(?:p\d+)?)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (openssh.Success)
                return openssh.Groups[1].Value;
        }

        var match = System.Text.RegularExpressions.Regex.Match(
            banner,
            @"(\d+(?:\.\d+)+(?:p\d+)?)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (!match.Success) return null;
        return match.Groups[1].Value;
    }

    private static void LoadExternalEntries()
    {
        var path = Environment.GetEnvironmentVariable("LMIST_CVE_DB_PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            var candidates = new[]
            {
                Path.Combine("config", "cve-database.json"),
                Path.Combine(AppContext.BaseDirectory, "config", "cve-database.json"),
            };
            path = candidates.FirstOrDefault(File.Exists);
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            var items = JsonSerializer.Deserialize<List<ExternalCveEntry>>(
                json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (items == null) return;

            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item.Cve)) continue;
                if (_entries.Any(e => e.Cve.Equals(item.Cve, StringComparison.OrdinalIgnoreCase))) continue;

                _entries.Add(new CveEntry(
                    item.Cve,
                    item.Name ?? item.Cve,
                    item.Port,
                    item.Service ?? "?",
                    item.Risk ?? "medium",
                    item.MatchBanner ?? "",
                    item.DetectProbe ?? "",
                    item.Fix ?? "参考官方公告",
                    item.CanMatchBanner,
                    item.AffectedRanges,
                    item.Conditions,
                    item.Reference));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Failed to load CVE database: {ex.Message}");
        }
    }

    private sealed class ExternalCveEntry
    {
        public string? Cve { get; set; }
        public string? Name { get; set; }
        public int Port { get; set; }
        public string? Service { get; set; }
        public string? Risk { get; set; }
        public string? MatchBanner { get; set; }
        public string? DetectProbe { get; set; }
        public string? Fix { get; set; }
        public bool CanMatchBanner { get; set; } = true;
        public AffectedVersionRange[]? AffectedRanges { get; set; }
        public string? Conditions { get; set; }
        public string? Reference { get; set; }
    }
}
