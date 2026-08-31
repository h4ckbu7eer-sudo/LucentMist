using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent;

internal static class CertificateValidityEvidence
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);

    internal static string? Describe(JsonElement root) => ReadExpiry(root) is { } expiry
        ? $"叶证书到期时间（UTC）：{expiry:yyyy-MM-dd HH:mm:ss}；如需描述日期，必须引用该观测值，不从当前年份或CVE年份推断。"
        : null;

    private static DateTimeOffset? ReadExpiry(JsonElement root)
    {
        if ((root.TryGetProperty("notAfterUtc", out var node) || root.TryGetProperty("notAfter", out node)) &&
            node.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(node.GetString(), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var expiry)) return expiry.ToUniversalTime();
        return null;
    }

    internal static IEnumerable<string> FindConflicts(string answer, IReadOnlyCollection<ReActObservation> observations)
    {
        var years = new HashSet<int>();
        foreach (var observation in observations.Where(item => item.Success && item.ToolName == "ssl_check"))
        {
            try
            {
                using var doc = JsonDocument.Parse(observation.Result);
                if (ReadExpiry(doc.RootElement) is { } expiry) years.Add(expiry.Year);
                // A conclusion may legitimately refer to an intermediate certificate.
                if (doc.RootElement.TryGetProperty("chain", out var chain) && chain.ValueKind == JsonValueKind.Array)
                    foreach (var certificate in chain.EnumerateArray())
                        if (ReadExpiry(certificate) is { } chainExpiry) years.Add(chainExpiry.Year);
            }
            catch (JsonException) { }
        }
        if (years.Count == 0) yield break;
        foreach (Match claim in Regex.Matches(answer,
                     @"(?<!\d)(?<year>\d{4})(?:\s*年(?:\s*\d{1,2}\s*月(?:\s*\d{1,2}\s*日)?)?|[-/]\d{1,2}[-/]\d{1,2})\s*(?:到期|过期|失效)|(?:到期时间|到期日期|expires(?: on| in)?)\s*[:：]?\s*(?<year>\d{4})",
                     RegexOptions.IgnoreCase, MatchTimeout))
        {
            var prefix = answer[..claim.Index].Split(['。', '；', ';', '，', ',', '\n']).Last();
            if (Regex.IsMatch(prefix, "不是|并非|不能|not ", RegexOptions.IgnoreCase, MatchTimeout)) continue;
            if (!years.Contains(int.Parse(claim.Groups["year"].Value, CultureInfo.InvariantCulture)))
                yield return $"证书到期年份与 ssl_check 不符；已观测证书到期年份为 {string.Join('/', years.Order())}。请引用 notAfterUtc，或省略没有把握的日期，不必重复探测";
        }
    }
}
