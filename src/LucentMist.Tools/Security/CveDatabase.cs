using System.Text.Json;

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
        bool CanMatchBanner = true
    );

    private static readonly List<CveEntry> _entries = new()
    {
        new("CVE-2017-0144", "EternalBlue", 445, "SMB",
            "critical", "SMBv1", "smbv1",
            "安装补丁 KB4012212，禁用 SMBv1"),

        new("CVE-2020-0796", "SMBGhost", 445, "SMB",
            "critical", "SMBv3.1.1", "smbv3",
            "安装补丁 KB4551762，启用 SMB 签名"),

        new("CVE-2023-38408", "OpenSSH RCE", 22, "SSH",
            "high", "OpenSSH < 9.3.2", "openssh_version",
            "升级 OpenSSH 到 9.3p2+"),

        new("CVE-2023-44487", "HTTP/2 Rapid Reset", 80, "HTTP",
            "high", "nginx < 1.25.3", "http_version",
            "升级 nginx 到 1.25.3+"),

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
    };

    public static IReadOnlyList<CveEntry> Entries => _entries;

    static CveDatabase()
    {
        LoadExternalEntries();
    }

    public static CveEntry? FindByCve(string cveId) =>
        Entries.FirstOrDefault(e => e.Cve.Equals(cveId, StringComparison.OrdinalIgnoreCase));

    public static CveEntry[] Lookup(int port) =>
        Entries.Where(e => e.Port == port).ToArray();

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
                var minVersion = parts[1].Trim();
                var bannerLower = banner.ToLower();
                return bannerLower.Contains(parts[0].Trim().ToLower()) &&
                       ExtractVersion(banner) is string ver &&
                       CompareVersion(ver, minVersion) < 0;
            }
            return banner.Contains(e.MatchBanner, StringComparison.OrdinalIgnoreCase);
        }).ToArray();
    }

    internal static string? ExtractVersion(string banner)
    {
        // Extract version like: "OpenSSH_8.9p1" → "8.9.1"
        // "nginx/1.24.0" → "1.24.0"
        // "SMBv1" → "1.0.0"
        if (banner.Contains("SMBv1", StringComparison.OrdinalIgnoreCase)) return "1.0.0";
        if (banner.Contains("SMBv2", StringComparison.OrdinalIgnoreCase)) return "2.0.0";
        if (banner.Contains("SMBv3", StringComparison.OrdinalIgnoreCase)) return "3.0.0";

        // "SSH-2.0-OpenSSH_8.9p1" 必须取产品版本 8.9.1，而不是协议版本 2.0
        if (banner.Contains("OpenSSH_", StringComparison.OrdinalIgnoreCase))
        {
            var openssh = System.Text.RegularExpressions.Regex.Match(
                banner,
                @"OpenSSH[_-]?(?:for[_-]?Windows[_-]?)?(\d+(?:\.\d+)+(?:p\d+)?)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (openssh.Success)
                return openssh.Groups[1].Value.Replace("p", ".");
        }

        var match = System.Text.RegularExpressions.Regex.Match(banner, @"(\d+\.\d+(?:\.\d+)?(?:p\d+)?)");
        if (!match.Success) return null;
        return match.Groups[1].Value.Replace("p", ".");
    }

    private static int CompareVersion(string a, string b)
    {
        var ap = a.Split('.').Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();
        var bp = b.Split('.').Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();
        for (int i = 0; i < Math.Max(ap.Length, bp.Length); i++)
        {
            var av = i < ap.Length ? ap[i] : 0;
            var bv = i < bp.Length ? bp[i] : 0;
            if (av != bv) return av.CompareTo(bv);
        }
        return 0;
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
                    item.Fix ?? "参考官方公告"));
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
    }
}
