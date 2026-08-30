using System.Text;
using System.Text.Json;
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
