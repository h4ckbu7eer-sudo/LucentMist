using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

/// <summary>Review order, not exploit probability or proof of an affected target.</summary>
public static class CloudLeadRanking
{
    public const int PerPortLimit = 3;
    public const string NextStep = "先登录设备管理端确认厂商、型号和固件/服务版本，再对照厂商安全公告与受影响范围；不要仅凭这些关键词线索认定漏洞或执行利用。";

    public static JsonElement[] Rank(IEnumerable<JsonElement> candidates) => candidates.Select(Annotate)
        .OrderByDescending(item => item["relevanceScore"]!.GetValue<int>())
        .ThenByDescending(item => item["referenceCount"]!.GetValue<int>())
        .ThenByDescending(item => item["cveYear"]!.GetValue<int>())
        .ThenByDescending(item => SourcePriority(item["source"]?.GetValue<string>() ?? ""))
        .ThenBy(item => item["cve"]?.GetValue<string>(), StringComparer.Ordinal)
        .Select(item => JsonSerializer.SerializeToElement(item)).ToArray();

    public static JsonElement[] Group(IEnumerable<JsonElement> ranked) => ranked
        .GroupBy(item => item.GetProperty("port").GetInt32()).OrderBy(group => group.Key)
        .Select(group => JsonSerializer.SerializeToElement(new
        {
            port = group.Key,
            totalCount = group.Count(),
            omittedCount = Math.Max(0, group.Count() - PerPortLimit),
            leads = group.Take(PerPortLimit).ToArray(),
            nextStep = NextStep,
            limitation = "按可观察相关性排序，均为待核实线索，不是目标漏洞；年份/引用数仅用于同相关性排序，不代表正在被利用。",
        })).ToArray();

    private static JsonObject Annotate(JsonElement candidate)
    {
        var item = JsonNode.Parse(candidate.GetRawText())!.AsObject();
        var port = item["port"]!.GetValue<int>();
        var description = item["name"]?.GetValue<string>() ?? "";
        description = description[..Math.Min(8192, description.Length)];
        var banner = item["banner"]?.GetValue<string>();
        var product = ServiceFingerprint.FromBanner(banner)?.ProductKey;
        var reasons = new List<string>();
        var score = 0;
        if (product != null && ContainsToken(description, product))
        {
            score += 100;
            reasons.Add("公告提及已识别产品（版本仍未验证）");
        }
        var protocol = port switch
        {
            53 => "dns",
            80 or 443 or 8080 or 8443 => "http",
            22 => "ssh",
            139 or 445 => "smb",
            3389 => "rdp",
            _ => null,
        };
        if (protocol != null && (ContainsToken(description, protocol) ||
                                protocol == "http" && ContainsToken(description, "https")))
        {
            score += 20;
            reasons.Add("公告提及受检服务协议（不证明同一产品）");
        }
        if (ContainsToken(description, port.ToString(System.Globalization.CultureInfo.InvariantCulture)))
        {
            score += 10;
            reasons.Add("公告提及受检端口");
        }
        var cve = item["cve"]?.GetValue<string>() ?? "";
        var year = cve.Length >= 9 && int.TryParse(cve.AsSpan(4, 4), out var parsed) && parsed <= DateTime.UtcNow.Year ? parsed : 0;
        item["relevanceScore"] = score;
        item["relevanceReason"] = reasons.Count == 0 ? "仅云源搜索命中，未找到额外目标相关证据" : string.Join("；", reasons);
        item["cveYear"] = year;
        item["referenceCount"] = Math.Clamp(item["referenceCount"]?.GetValue<int>() ?? 0, 0, 1000);
        return item;
    }

    private static bool ContainsToken(string text, string token) => Regex.IsMatch(text,
        $@"(?<![a-z0-9]){Regex.Escape(token)}(?![a-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private static int SourcePriority(string source) => source.Contains("NVD", StringComparison.OrdinalIgnoreCase) ? 3
        : source.Contains("Shodan", StringComparison.OrdinalIgnoreCase) ? 2 : 1;
}
