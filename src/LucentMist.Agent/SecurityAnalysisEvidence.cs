using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent;

internal static class SecurityAnalysisEvidence
{
    internal static IReadOnlyList<string> FindIncompleteChecks(
        string userQuery,
        IReadOnlyCollection<ReActObservation> observations)
    {
        if (!RequiresSecurityConclusion(userQuery)) return [];

        var targets = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
        foreach (var observation in observations.Where(item => item.Success &&
                     item.ToolName is "port_scan" or "vuln_scan"))
        {
            if (!TryReadTargetAndOpenPorts(observation.Result, out var target, out var ports)) continue;
            if (!targets.TryGetValue(target, out var knownPorts))
            {
                knownPorts = [];
                targets[target] = knownPorts;
            }
            knownPorts.UnionWith(ports);
        }

        var incomplete = new List<string>();
        foreach (var (target, openPorts) in targets)
        {
            var vulnerabilityObservation = observations.LastOrDefault(item =>
                item.Success && item.ToolName == "vuln_scan" && ResultTargets(item.Result, target));
            if (openPorts.Count > 0 && vulnerabilityObservation == null)
            {
                incomplete.Add($"{target} 的开放端口尚未完成漏洞匹配");
            }
            else if (vulnerabilityObservation != null)
            {
                var checkedPorts = ReadCheckedServicePorts(vulnerabilityObservation.Result);
                var missingPorts = openPorts.Except(checkedPorts).Order().ToArray();
                if (missingPorts.Length > 0)
                    incomplete.Add($"{target} 的端口 {string.Join(',', missingPorts)} 尚未进入漏洞分析");
            }

            if (openPorts.Contains(443) && !observations.Any(item =>
                    item.Success && item.ToolName == "ssl_check" &&
                    ResultTargetsPort(item.Result, target, 443)))
                incomplete.Add($"{target}:443 的 TLS 检查失败或尚未完成");

            if (openPorts.Contains(53) && !HasDnsAssessment(observations, target))
                incomplete.Add($"{target}:53 的 DNS 版本/递归检查失败或尚未完成");
        }

        return incomplete;
    }

    internal static void AppendVulnerabilitySummary(StringBuilder sb, JsonElement root)
    {
        var total = root.TryGetProperty("totalFindings", out var totalNode) ? totalNode.GetInt32() : 0;
        var sources = root.TryGetProperty("sourcesConsulted", out var sourcesNode) &&
                      sourcesNode.ValueKind == JsonValueKind.Array
            ? string.Join(" + ", sourcesNode.EnumerateArray().Select(item => item.GetString())
                .Where(item => !string.IsNullOrWhiteSpace(item)))
            : root.TryGetProperty("source", out var sourceNode)
                ? sourceNode.GetString() ?? "未注明"
                : "未注明";
        sb.AppendLine($"  漏洞结论: {(total == 0 ? "未发现版本匹配的漏洞" : $"发现 {total} 个匹配项")}");
        sb.AppendLine($"  数据来源: {sources}");
        if (root.TryGetProperty("findings", out var findingsNode) &&
            findingsNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var finding in findingsNode.EnumerateArray())
            {
                var cve = finding.TryGetProperty("cve", out var cveNode) ? cveNode.GetString() ?? "未编号" : "未编号";
                var name = finding.TryGetProperty("name", out var nameNode) ? nameNode.GetString() ?? "未命名" : "未命名";
                var cvss = finding.TryGetProperty("cvss", out var cvssNode) && cvssNode.TryGetDouble(out var score)
                    ? score.ToString("F1")
                    : "未知";
                var fix = finding.TryGetProperty("fix", out var fixNode) ? fixNode.GetString() ?? "参考厂商公告" : "参考厂商公告";
                var source = finding.TryGetProperty("source", out var findingSourceNode)
                    ? findingSourceNode.GetString() ?? "未注明"
                    : "未注明";
                sb.AppendLine($"  - {cve} {name} | CVSS {cvss} | 来源 {source} | 修复: {fix}");
            }
        }
        if (total == 0 && root.TryGetProperty("noMatchReason", out var reasonNode))
            sb.AppendLine($"  判断依据: {reasonNode.GetString()}");
        if (root.TryGetProperty("checkedServices", out var checkedNode) &&
            checkedNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var service in checkedNode.EnumerateArray())
            {
                var port = service.TryGetProperty("port", out var portNode) ? portNode.GetInt32() : 0;
                var reason = service.TryGetProperty("reason", out var serviceReason)
                    ? serviceReason.GetString() ?? "未提供判断依据"
                    : "未提供判断依据";
                sb.AppendLine($"  端口 {port} 判断: {reason}");
            }
        }
    }

    internal static void AppendTlsSummary(StringBuilder sb, JsonElement root)
    {
        var trusted = root.TryGetProperty("isTrusted", out var trustedNode) && trustedNode.GetBoolean();
        var expired = root.TryGetProperty("isExpired", out var expiredNode) && expiredNode.GetBoolean();
        sb.AppendLine($"  TLS 结论: {(trusted && !expired ? "证书有效且信任校验通过" : "证书检查已完成，但存在信任或有效期风险")}");
        if (root.TryGetProperty("securityConclusion", out var conclusionNode))
            sb.AppendLine($"  判断依据: {conclusionNode.GetString()}");
        if (root.TryGetProperty("trustErrors", out var errors) && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
        {
            sb.AppendLine($"  HTTPS 信任风险: {string.Join(", ", errors.EnumerateArray().Select(item => item.GetString()))}");
            sb.AppendLine("  不能可靠确认 HTTPS 服务身份，可能增加中间人风险；不等于已遭攻击。请核对证书名称和完整信任链，不要直接忽略警告。");
        }
    }

    internal static IReadOnlyList<string> FindConclusionConflicts(string answer, IReadOnlyCollection<ReActObservation> observations)
    {
        var conflicts = new List<string>();
        foreach (var observation in observations.Where(item => item.Success && item.ToolName is "ssl_check" or "service_identify"))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                var root = doc.RootElement;
                if (observation.ToolName == "ssl_check" && root.TryGetProperty("trustErrors", out var errors) &&
                    errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0 &&
                    (!answer.Contains("信任", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(answer,
                        @"(?:证书|TLS|HTTPS)[^。\n]{0,150}(?:属正常|无风险|无需关注)", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))))
                    conflicts.Add("HTTPS 信任校验有错误：必须说明身份校验/中间人风险，不得因自签常见就称为正常或无风险");
                if (root.TryGetProperty("dnsSecurity", out var dns) && dns.ValueKind == JsonValueKind.Object &&
                    dns.TryGetProperty("recursionAvailable", out var recursion) && recursion.ValueKind == JsonValueKind.True &&
                    Regex.IsMatch(answer, @"未(?:对[^。\n]{0,20})?开放递归|未(?:对[^。\n]{0,20})?开启递归|递归[^。\n]{0,20}(?:未开放|未开启)",
                        RegexOptions.None, TimeSpan.FromMilliseconds(100)))
                    conflicts.Add("DNS 工具已观察到对当前扫描源开放递归，不能总结为未开放；公网可达性尚未检查");
            }
            catch (JsonException) { }
        }
        return conflicts.Distinct().ToArray();
    }

    internal static string WithVerifiedFacts(string query, string answer, IReadOnlyCollection<ReActObservation> observations)
    {
        if (!RequiresSecurityConclusion(query)) return answer;
        var facts = new StringBuilder();
        foreach (var observation in observations.Where(item => item.Success))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                var root = doc.RootElement;
                var target = root.TryGetProperty("target", out var node) ? node.GetString() : null;
                if (observation.ToolName == "ssl_check")
                {
                    facts.AppendLine($"{target} HTTPS 核验：");
                    AppendTlsSummary(facts, root);
                }
                if (observation.ToolName == "service_identify" && root.TryGetProperty("dnsSecurity", out var dns) &&
                    dns.ValueKind == JsonValueKind.Object && dns.TryGetProperty("recursionAssessment", out var assessment))
                    facts.AppendLine($"{target} DNS 核验：{assessment.GetString()}（仅当前扫描视角，未验证公网可达性）");
                if (observation.ToolName == "vuln_scan")
                {
                    facts.AppendLine($"{target} 漏洞核验：");
                    AppendVulnerabilitySummary(facts, root);
                    if (root.TryGetProperty("cloudCandidateGroups", out var groups))
                    {
                        foreach (var group in groups.EnumerateArray())
                            facts.AppendLine($"  端口 {group.GetProperty("port")} 优先核实（非目标漏洞）：" +
                                string.Join(", ", group.GetProperty("leads").EnumerateArray().Select(lead => lead.GetProperty("cve").GetString())));
                        if (root.TryGetProperty("cloudNextStep", out var next)) facts.AppendLine($"  下一步：{next.GetString()}");
                    }
                }
            }
            catch (JsonException) { }
        }
        return facts.Length == 0 ? answer : answer + "\n\n【工具核验事实（非模型推断）】\n" + facts.ToString().TrimEnd();
    }

    private static bool RequiresSecurityConclusion(string query) =>
        new[] { "安全", "风险", "漏洞", "分析", "security", "risk", "vulnerability", "audit" }
            .Any(term => query.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static bool TryReadTargetAndOpenPorts(
        string json,
        out string target,
        out int[] ports)
    {
        target = string.Empty;
        ports = [];
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            target = root.TryGetProperty("target", out var targetNode)
                ? targetNode.GetString() ?? string.Empty
                : string.Empty;
            ports = root.TryGetProperty("openPorts", out var portsNode) &&
                    portsNode.ValueKind == JsonValueKind.Array
                ? portsNode.EnumerateArray().Select(item => item.GetInt32()).ToArray()
                : [];
            return target.Length > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool ResultTargets(string json, string target)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("target", out var targetNode) &&
                   string.Equals(targetNode.GetString(), target, StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool ResultTargetsPort(string json, string target, int port)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            return root.TryGetProperty("target", out var targetNode) &&
                   string.Equals(targetNode.GetString(), target, StringComparison.OrdinalIgnoreCase) &&
                   root.TryGetProperty("port", out var portNode) && portNode.GetInt32() == port;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static HashSet<int> ReadCheckedServicePorts(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("checkedServices", out var checkedNode) &&
                   checkedNode.ValueKind == JsonValueKind.Array
                ? checkedNode.EnumerateArray()
                    .Where(item => item.TryGetProperty("port", out _))
                    .Select(item => item.GetProperty("port").GetInt32())
                    .ToHashSet()
                : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static bool HasDnsAssessment(
        IReadOnlyCollection<ReActObservation> observations,
        string target) =>
        observations.Any(item =>
        {
            if (!item.Success || item.ToolName != "service_identify") return false;
            try
            {
                using var document = JsonDocument.Parse(item.Result);
                var root = document.RootElement;
                return root.TryGetProperty("target", out var targetNode) &&
                       string.Equals(targetNode.GetString(), target, StringComparison.OrdinalIgnoreCase) &&
                       root.TryGetProperty("port", out var portNode) && portNode.GetInt32() == 53 &&
                       root.TryGetProperty("dnsSecurity", out var dnsNode) &&
                       dnsNode.ValueKind == JsonValueKind.Object;
            }
            catch (JsonException)
            {
                return false;
            }
        });
}
