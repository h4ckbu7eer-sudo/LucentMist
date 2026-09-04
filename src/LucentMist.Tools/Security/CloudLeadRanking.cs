using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

/// <summary>Review order, not exploit probability or proof of an affected target.</summary>
public static class CloudLeadRanking
{
    public const int PerPortLimit = 3;
    public const int ModelLeadLimit = 5;
    public const string NextStep = "先登录设备管理端确认厂商、型号和固件/服务版本，再对照厂商安全公告与受影响范围；不要仅凭这些关键词线索认定漏洞或执行利用。";

    public static JsonElement[] Rank(IEnumerable<JsonElement> candidates, OsHint? os = null) => candidates.Select(item => Annotate(item, os))
        .OrderBy(item => item["historicalUnverified"]!.GetValue<bool>())
        .ThenByDescending(item => item["relevanceScore"]!.GetValue<int>())
        .ThenByDescending(item => item["hasCvss"]!.GetValue<bool>())
        .ThenByDescending(item => item["cveYear"]!.GetValue<int>())
        .ThenByDescending(item => item["referenceCount"]!.GetValue<int>())
        .ThenByDescending(item => SourcePriority(item["source"]?.GetValue<string>() ?? ""))
        .ThenBy(item => item["cve"]?.GetValue<string>(), StringComparer.Ordinal)
        .Select(item => JsonSerializer.SerializeToElement(item)).ToArray();

    public static JsonElement[] Group(IEnumerable<JsonElement> ranked) => ranked
        .GroupBy(item => item.GetProperty("port").GetInt32()).OrderBy(group => group.Key)
        .Select(group => JsonSerializer.SerializeToElement(new
        {
            port = group.Key,
            totalCount = group.Count(),
            omittedCount = group.Count() - Math.Min(PerPortLimit, group.Count(IsRelevantForPresentation)),
            historicalCount = group.Count(item => item.GetProperty("historicalUnverified").GetBoolean()),
            withoutProductEvidenceCount = group.Count(item => !item.GetProperty("productEvidence").GetBoolean()),
            leads = group.Where(IsRelevantForPresentation).Take(PerPortLimit).ToArray(),
            nextStep = NextStep,
            limitation = "按可观察相关性排序，均为待核实线索，不是目标漏洞；年份/引用数仅用于同相关性排序，不代表正在被利用。",
        })).ToArray();

    public static JsonElement[] ForPresentation(IEnumerable<JsonElement> groups)
    {
        var array = groups.ToArray();
        static string Key(JsonElement lead) => $"{lead.GetProperty("port")}:{lead.GetProperty("cve")}";
        var selected = Rank(array.SelectMany(group => group.GetProperty("leads").EnumerateArray()))
            .Take(ModelLeadLimit).Select(Key).ToHashSet(StringComparer.Ordinal);
        return array.Select(group =>
        {
            var node = JsonNode.Parse(group.GetRawText())!.AsObject();
            var all = group.GetProperty("leads").EnumerateArray().ToArray();
            var retained = all.Where(lead => selected.Contains(Key(lead))).ToArray();
            node["modelOmittedCount"] = all.Length - retained.Length;
            node["leads"] = JsonSerializer.SerializeToNode(retained);
            return JsonSerializer.SerializeToElement(node);
        }).ToArray();
    }

    public static int CountForPresentation(IEnumerable<JsonElement> groups) =>
        ForPresentation(groups).Sum(group => group.GetProperty("leads").GetArrayLength());

    private static JsonObject Annotate(JsonElement candidate, OsHint? os)
    {
        var item = JsonNode.Parse(candidate.GetRawText())!.AsObject();
        var port = item["port"]!.GetValue<int>();
        var description = item["name"]?.GetValue<string>() ?? "";
        description = description[..Math.Min(8192, description.Length)];
        var banner = item["banner"]?.GetValue<string>();
        var product = ServiceFingerprint.FromBanner(banner)?.ProductKey;
        var reasons = new List<string>();
        var score = 0;
        os ??= item["osEvidence"]?.Deserialize<OsHint>();
        if (os != null)
        {
            item["osEvidence"] = JsonSerializer.SerializeToNode(os);
            if (ContainsToken(description, os.Family))
            {
                score += 5;
                reasons.Add("公告与 OS 推测一致（仅排序，不证明适用或排除其它平台）");
            }
        }
        var productMatch = product != null && ContainsToken(description, product);
        if (productMatch)
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
        item["productEvidence"] = productMatch || item["versionStatus"]?.GetValue<string>() == "verified" || item["versionVerified"]?.GetValue<bool>() == true;
        item["relevanceReason"] = reasons.Count == 0 ? "仅云源搜索命中，未找到额外目标相关证据" : string.Join("；", reasons);
        item["cveYear"] = year;
        item["historicalUnverified"] = year is > 0 and < 2005 &&
            item["versionStatus"]?.GetValue<string>() != "verified" && item["versionVerified"]?.GetValue<bool>() != true;
        item["hasCvss"] = item["cvss"] is JsonValue value && value.TryGetValue<double>(out var cvss) && cvss > 0;
        item["referenceCount"] = Math.Clamp(item["referenceCount"]?.GetValue<int>() ?? 0, 0, 1000);
        return item;
    }

    private static bool ContainsToken(string text, string token) => Regex.IsMatch(text,
        $@"(?<![a-z0-9]){Regex.Escape(token)}(?![a-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private static bool IsRelevantForPresentation(JsonElement item) =>
        !item.GetProperty("historicalUnverified").GetBoolean() && item.GetProperty("productEvidence").GetBoolean();

    private static int SourcePriority(string source) => source.Contains("NVD", StringComparison.OrdinalIgnoreCase) ? 3
        : source.Contains("Shodan", StringComparison.OrdinalIgnoreCase) ? 2 : 1;
}
