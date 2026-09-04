using System.Text.Json;
using System.Text.RegularExpressions;
using LucentMist.Agent.LLM;
using LucentMist.Tools.Common;

namespace LucentMist.Agent;

internal static class PortScopeEvidence
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);
    private const string Negative = @"未发现|未开放|没有开放|已关闭|不开放|not open|closed";

    internal static IEnumerable<string> FindConflicts(string answer, IReadOnlyCollection<ReActObservation> observations)
    {
        var scopes = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
        var udpStates = new Dictionary<string, Dictionary<int, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var observation in observations.Where(item => item.Success && item.ToolName == "port_scan"))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                var root = doc.RootElement;
                if (!root.TryGetProperty("target", out var target) || !root.TryGetProperty("scannedPortRange", out var range) ||
                    !PortHelper.TryParsePorts(range.GetString() ?? "", out var ports)) continue;
                var key = target.GetString() ?? "";
                if (!scopes.TryGetValue(key, out var combined)) scopes[key] = combined = [];
                combined.UnionWith(ports);
            }
            catch (JsonException) { }
        }

        foreach (var observation in observations.Where(item => item.Success && item.ToolName == "udp_scan"))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                var root = doc.RootElement;
                var target = root.TryGetProperty("target", out var targetNode) ? targetNode.GetString() ?? "" : "";
                if (target.Length == 0 || !root.TryGetProperty("ports", out var portsNode) || portsNode.ValueKind != JsonValueKind.Array) continue;
                if (!udpStates.TryGetValue(target, out var states)) udpStates[target] = states = [];
                foreach (var item in portsNode.EnumerateArray())
                    if (item.TryGetProperty("port", out var portNode) && item.TryGetProperty("state", out var stateNode))
                        states[portNode.GetInt32()] = stateNode.GetString() ?? "unknown";
            }
            catch (JsonException) { }
        }

        if (scopes.Count == 0) yield break;
        foreach (var clause in Regex.Split(answer, @"[。；;\n]", RegexOptions.None, MatchTimeout))
        {
            if (Regex.IsMatch(clause, @"不能|不可|不得|不应|无法|不代表|不等于|cannot|can't", RegexOptions.IgnoreCase, MatchTimeout)) continue;
            var namedTargets = scopes.Keys.Where(target => clause.Contains(target, StringComparison.OrdinalIgnoreCase)).ToArray();
            var applicable = namedTargets.Length > 0 ? namedTargets : scopes.Keys.ToArray();
            // Remove addresses, CVE identifiers and version-like tokens before
            // finding arbitrary numeric ports; these are not port claims.
            var text = Regex.Replace(clause, @"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b|\bCVE-\d{4}-\d+\b|\b\d+(?:\.\d+)+\b", " ", RegexOptions.IgnoreCase, MatchTimeout);
            // The inverse error is also misleading: a port inside a recorded
            // TCP scan must not be presented as outside that scan. Only check
            // explicit port-scope claims, not unfinished TLS/UDP/service checks.
            if (!Regex.IsMatch(text, "UDP|TLS|证书|漏洞匹配", RegexOptions.IgnoreCase, MatchTimeout))
                foreach (Match unknown in Regex.Matches(text,
                             @"(?:范围外端口|未扫描端口|未检查端口|端口)\s*[（(]?(?:如\s*)?(?<ports>\d+(?:\s*[,，、/]\s*\d+)*)[）)]?\s*(?:未检查|未扫描|不在扫描范围)?|(?<ports>\d+)\s*端口\s*(?:未检查|未扫描)",
                             RegexOptions.None, MatchTimeout))
                {
                    if (!Regex.IsMatch(unknown.Value, "范围外|未检查|未扫描|不在扫描范围", RegexOptions.None, MatchTimeout)) continue;
                    foreach (Match number in Regex.Matches(unknown.Groups["ports"].Value, @"\d+", RegexOptions.None, MatchTimeout))
                        if (int.TryParse(number.Value, out var checkedPort) && applicable.All(target => scopes[target].Contains(checkedPort)))
                            yield return $"端口 {checkedPort} 已在所述目标的 TCP 受检范围内，不能列为范围外或未检查；未观察开放不等于服务已全面评估，不必重新扫描";
                }
            if (!Regex.IsMatch(text, Negative, RegexOptions.IgnoreCase, MatchTimeout)) continue;
            text = Regex.Replace(text, @"\d{1,5}\s*(?:端口)?\s*(?:未知|未检查|未扫描|未检验)", " ", RegexOptions.None, MatchTimeout);
            var claims = Regex.Matches(text, $@"(?:{Negative})\s*(?<subject>(?:(?!但|未知|未检查|未扫描|不在|范围外).){{0,60}})|(?<subject>[a-zA-Z0-9][a-zA-Z0-9 /,，、()（）-]{{0,59}})(?:端口)?\s*(?:{Negative})", RegexOptions.IgnoreCase, MatchTimeout);
            foreach (Match claim in claims)
            {
                var subject = claim.Groups["subject"].Value;
                var mentioned = Regex.Matches(subject, @"(?<![a-zA-Z0-9_.-])\d{1,5}(?![a-zA-Z0-9_.-])", RegexOptions.None, MatchTimeout)
                    .Select(match => int.Parse(match.Value)).Where(port => port is >= 1 and <= 65535).ToHashSet();
                foreach (var (port, service) in PortHelper.TcpServices)
                    if (Regex.IsMatch(subject, $@"(?<![a-z]){Regex.Escape(service)}(?![a-z])", RegexOptions.IgnoreCase, MatchTimeout)) mentioned.Add(port);
                foreach (var target in applicable)
                    foreach (var port in mentioned.Except(scopes[target]))
                    {
                        if (udpStates.TryGetValue(target, out var states) && states.TryGetValue(port, out var state))
                        {
                            if (state is "unprobeable" or "open|filtered" or "open")
                                yield return $"{target} 的 UDP {port} 状态为 {state}，不能断言未开放；这是 UDP 不确定性，不是 TCP 范围外问题";
                            continue;
                        }
                        yield return $"{target} 的端口 {port} 不在已记录的 TCP 受检范围内，不能断言未开放；请明确范围外未知，不必扩大扫描";
                    }
            }
        }
    }
}
