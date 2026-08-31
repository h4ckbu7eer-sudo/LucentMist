using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent;

internal static class SecurityAnalysisEvidence
{
    internal const string TlsTrustGuidance = "不要通过忽略、关闭或跳过证书校验绕过信任错误，即使目标在内网。" +
        "应先经可信管理渠道核实设备身份、证书名称和完整链；仅在核实来源后配置信任，不能把忽略告警当成修复。";

    internal static IReadOnlyList<string> FindIncompleteChecks(
        string userQuery,
        IReadOnlyCollection<ReActObservation> observations,
        bool includeFailedAttempts = true)
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
        if (targets.Count == 0 && (includeFailedAttempts || !observations.Any(item => item.ToolName is "port_scan" or "vuln_scan")) &&
            Regex.IsMatch(userQuery, @"网关|网络|子网|\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.None, TimeSpan.FromMilliseconds(100)))
            incomplete.Add("尚未检查目标端口暴露面");
        foreach (var (target, openPorts) in targets)
        {
            var vulnerabilityObservation = observations.LastOrDefault(item =>
                item.Success && item.ToolName == "vuln_scan" && ResultTargets(item.Result, target));
            if (openPorts.Count > 0 && vulnerabilityObservation == null &&
                (includeFailedAttempts || !Attempted("vuln_scan", target)))
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

            if (openPorts.Contains(443) && (includeFailedAttempts || !Attempted("ssl_check", target, 443)) && !observations.Any(item =>
                    item.Success && item.ToolName == "ssl_check" &&
                    ResultTargetsPort(item.Result, target, 443)))
                incomplete.Add($"{target}:443 的 TLS 检查失败或尚未完成");

            if (openPorts.Contains(53) && (includeFailedAttempts || !Attempted("service_identify", target, 53)) && !HasDnsAssessment(observations, target))
                incomplete.Add($"{target}:53 的 DNS 版本/递归检查失败或尚未完成");
        }

        return incomplete;

        bool Attempted(string tool, string target, int? port = null) => observations.Any(item =>
            !item.Success && item.ToolName == tool && (port.HasValue
                ? ResultTargetsPort(item.Input, target, port.Value) : ResultTargets(item.Input, target)));
    }

    internal static string LimitedAssessment(string query, IReadOnlyCollection<ReActObservation> observations)
    {
        var sb = new StringBuilder("【有限安全评估】以下结论受限于未确认项；检查完成不等于目标安全。\n");
        foreach (var group in observations.Where(item => item.Success && item.ToolName is "port_scan" or "vuln_scan")
                     .Select(item => TryReadTargetAndOpenPorts(item.Result, out var target, out var ports)
                         ? (Target: target, Ports: ports) : (Target: "", Ports: Array.Empty<int>()))
                     .Where(item => item.Target.Length > 0).GroupBy(item => item.Target))
            sb.AppendLine($"暴露面 {group.Key}：受检开放端口 {string.Join(", ", group.SelectMany(item => item.Ports).Distinct().Order())}（仅本次扫描视角）。");

        // Keep successful evidence, not internal correction/contract failures, in the user assessment.
        var facts = WithVerifiedFacts(query, "", observations);
        if (facts.Length > 0) sb.AppendLine(facts.Trim());
        foreach (var missing in FindIncompleteChecks(query, observations)) sb.AppendLine($"未确认：{missing}。");
        foreach (var failure in observations.Where(item => !item.Success &&
                     item.ToolName is "port_scan" or "vuln_scan" or "ssl_check" or "service_identify")
                     .GroupBy(item => (item.ToolName, item.Input)).Select(group => group.Last())
                     .Where(failure => !observations.Any(item => item.Success && item.ToolName == failure.ToolName && item.Input == failure.Input)))
            sb.AppendLine($"检查受限 {failure.ToolName}：{failure.Result}");
        sb.AppendLine("下一步：优先核对 HTTPS 设备身份和完整证书链，不绕过信任校验；限制管理端口仅授权网段可达。");
        sb.AppendLine("登录设备管理端查询厂商、型号、固件/服务版本，对照厂商补丁公告；DNS 不确定项请复测并检查递归 ACL。版本未知不能确认具体 CVE，未检查/检查失败不等于安全。");
        return sb.ToString().TrimEnd();
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
        if (root.TryGetProperty("cloudCandidateGroups", out var groups) && groups.ValueKind == JsonValueKind.Array)
        {
            foreach (var group in LucentMist.Tools.Security.CloudLeadRanking.ForPresentation(groups.EnumerateArray()))
            {
                var leads = group.GetProperty("leads").EnumerateArray().ToArray();
                sb.AppendLine($"  端口 {group.GetProperty("port")} 优先核实（非目标漏洞）：" +
                    (leads.Length > 0 ? string.Join(", ", leads.Select(lead => lead.GetProperty("cve").GetString())) : "无优先展示项；其余线索保留在原始结果中"));
                if (group.TryGetProperty("historicalCount", out var historical) && historical.GetInt32() > 0)
                    sb.AppendLine($"  已折叠 {historical.GetInt32()} 条历史且版本未验证的线索（未删除，不代表漏洞已修复）。");
            }
            if (root.TryGetProperty("cloudNextStep", out var next)) sb.AppendLine($"  下一步：{next.GetString()}");
        }
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
        var identity = TlsIdentityAssessment(root);
        if (identity != null) sb.AppendLine($"  证书身份依据: {identity}");
        if (root.TryGetProperty("trustErrors", out var errors) && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
        {
            sb.AppendLine($"  HTTPS 信任风险: {string.Join(", ", errors.EnumerateArray().Select(item => item.GetString()))}");
            sb.AppendLine("  不能可靠确认 HTTPS 服务身份，可能增加中间人风险；不等于已遭攻击。请核对证书名称和完整信任链，不要直接忽略警告。");
            sb.AppendLine($"  处置边界: {TlsTrustGuidance}");
        }
    }

    internal static string? TlsIdentityAssessment(JsonElement root)
    {
        if (!root.TryGetProperty("subject", out var subject) || subject.ValueKind != JsonValueKind.String ||
            !root.TryGetProperty("issuer", out var issuer) || issuer.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(subject.GetString()) || string.IsNullOrWhiteSpace(issuer.GetString()) ||
            string.Equals(subject.GetString(), issuer.GetString(), StringComparison.OrdinalIgnoreCase)) return null;
        return $"主体与签发者不同（subject={subject.GetString()}; issuer={issuer.GetString()}），" +
               "不能把该叶证书称为自签证书；链不完整也不能证明未取得的根证书是自签或可信。";
    }

    internal static IReadOnlyList<string> FindConclusionConflicts(string answer, IReadOnlyCollection<ReActObservation> observations)
    {
        var conflicts = new List<string>();
        var dnsEvidence = ReadDnsEvidence(observations);
        var hasPositiveDns = dnsEvidence.Any(item => item.Positive);
        // A TLS name mismatch is not an acknowledgement of conflicting DNS probes.
        // An explicit DNS disagreement may quote both positive and negative readings.
        var describesDnsDifference = Regex.IsMatch(answer,
            @"(?:DNS|递归)(?:(?!HTTPS|TLS|证书)[^\n]){0,120}(?:不一致|波动|差异|矛盾)",
            RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        if (hasPositiveDns && ClaimsNoRecursion(answer) && !describesDnsDifference)
            conflicts.Add("至少一次 DNS 探测观察到对当前扫描源开放递归，不能断言未开放；不同探测结果须说明差异");
        // A disagreement is a limitation, not an instruction to keep probing. The
        // deterministic facts below always disclose it; only contradictory claims block.
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
                if (observation.ToolName == "ssl_check" && TlsIdentityAssessment(root) is { } identity &&
                    ClaimsSelfSigned(answer))
                    conflicts.Add(identity + "请删除没有证据的自签断言，按主体、签发者及实际 trustErrors 描述。");
                if (observation.ToolName == "ssl_check" && root.TryGetProperty("trustErrors", out var trustErrors) &&
                    trustErrors.ValueKind == JsonValueKind.Array && trustErrors.GetArrayLength() > 0 && ClaimsVerificationBypass(answer))
                    conflicts.Add(TlsTrustGuidance);
            }
            catch (JsonException) { }
        }
        return conflicts.Distinct().ToArray();
    }

    private static bool ClaimsVerificationBypass(string answer)
    {
        foreach (Match match in Regex.Matches(answer, @"(?:忽略|跳过|关闭|禁用)[^。；\n]{0,20}(?:告警|警告|证书|信任|校验)",
                     RegexOptions.None, TimeSpan.FromMilliseconds(100)))
        {
            var clause = answer[..match.Index].Split(['。', '；', ';', '，', ',', '\n']).Last();
            if (!new[] { "不要", "不能", "不应", "不得", "不可", "不建议", "禁止", "避免", "勿", "不支持" }.Any(clause.Contains)) return true;
        }
        return false;
    }

    private static bool ClaimsSelfSigned(string answer)
    {
        foreach (Match match in Regex.Matches(answer, @"自签|self[- ]signed",
                     RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
        {
            // Scope negation to this clause: "不能断言自签（此处确为自签根）"
            // contains both a disclaimer and a separate unsupported assertion.
            var clause = answer[..match.Index].Split(['。', '；', ';', '，', ',', '\n', '（', '(']).Last();
            if (clause.TrimEnd().EndsWith("非", StringComparison.Ordinal)) continue;
            if (!Regex.IsMatch(clause, @"不能|不可|不得|不应|并非|不是|未确认|无法|不代表|不等于|是否|可能|尚未|不一定|cannot|not |unknown|may ",
                    RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))) return true;
        }
        return false;
    }

    private static bool ClaimsNoRecursion(string answer)
    {
        foreach (Match match in Regex.Matches(answer, @"未观察到[^。\n]{0,40}开放递归|未(?:对[^。\n]{0,20})?开放递归|未(?:对[^。\n]{0,20})?开启递归|递归[^。\n]{0,20}(?:未开放|未开启)",
                     RegexOptions.None, TimeSpan.FromMilliseconds(100)))
        {
            var prefix = answer[..match.Index].Split(['。', '；', '\n']).Last() + match.Value;
            if (!new[] { "不能", "不可", "不得", "不应", "并非", "不代表", "不等于" }.Any(prefix.Contains)) return true;
        }
        return false;
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
                }
            }
            catch (JsonException) { }
        }
        foreach (var target in DnsDisagreements(ReadDnsEvidence(observations)))
            facts.AppendLine($"{target} DNS 多次探测结果不一致：至少一次观察到递归响应，不能据另一次无响应认定已关闭。请复查 ACL/解析策略，公网可达性未确认。");
        return facts.Length == 0 ? answer : answer + "\n\n【工具核验事实（非模型推断）】\n" + facts.ToString().TrimEnd();
    }

    internal static string DnsDisagreementNote(IReadOnlyCollection<ReActObservation> observations) =>
        string.Join("\n", DnsDisagreements(ReadDnsEvidence(observations)).Select(target =>
            $"{target} DNS 多次探测结果不一致；至少一次观察到递归响应，不能断言递归已关闭。公网可达性未确认。"));

    private static List<string> DnsDisagreements(List<(string Target, bool Positive)> evidence) => evidence.GroupBy(item => item.Target)
        .Where(group => group.Select(item => item.Positive).Distinct().Count() > 1).Select(group => group.Key).ToList();

    private static List<(string Target, bool Positive)> ReadDnsEvidence(IReadOnlyCollection<ReActObservation> observations)
    {
        var evidence = new List<(string, bool)>();
        foreach (var observation in observations.Where(item => item.Success && item.ToolName is "service_identify" or "vuln_scan"))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                var root = doc.RootElement;
                var target = root.TryGetProperty("target", out var t) ? t.GetString() ?? "" : "";
                if (root.TryGetProperty("dnsSecurity", out var dns) && dns.ValueKind == JsonValueKind.Object &&
                    (!dns.TryGetProperty("recursionStatus", out var status) || status.GetString() != "unknown") &&
                    dns.TryGetProperty("recursionAvailable", out var recursion) && recursion.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    evidence.Add((target, recursion.GetBoolean()));
                if (root.TryGetProperty("checkedServices", out var services))
                    foreach (var service in services.EnumerateArray())
                        if (service.TryGetProperty("port", out var port) && port.GetInt32() == 53 && service.TryGetProperty("reason", out var reason))
                        {
                            var text = reason.GetString() ?? "";
                            if (text.StartsWith("对当前扫描源开放递归", StringComparison.Ordinal)) evidence.Add((target, true));
                            else if (text.StartsWith("未观察到对当前扫描源开放递归", StringComparison.Ordinal)) evidence.Add((target, false));
                        }
            }
            catch (JsonException) { }
        }
        return evidence;
    }

    internal static bool RequiresSecurityConclusion(string query) =>
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
                   root.TryGetProperty("port", out var portNode) && int.TryParse(portNode.ToString(), out var parsedPort) && parsedPort == port;
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
            if (!item.Success || item.ToolName is not ("service_identify" or "vuln_scan")) return false;
            try
            {
                using var document = JsonDocument.Parse(item.Result);
                var root = document.RootElement;
                return root.TryGetProperty("target", out var targetNode) &&
                       string.Equals(targetNode.GetString(), target, StringComparison.OrdinalIgnoreCase) &&
                       (item.ToolName == "vuln_scan" || root.TryGetProperty("port", out var portNode) && portNode.GetInt32() == 53) &&
                       root.TryGetProperty("dnsSecurity", out var dnsNode) &&
                       dnsNode.ValueKind == JsonValueKind.Object;
            }
            catch (JsonException)
            {
                return false;
            }
        });
}
