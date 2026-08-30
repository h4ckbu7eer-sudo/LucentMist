using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Tools.Security;

namespace LucentMist.Agent.Tests;

public class AgentObservationFormatterTests
{
    [Fact]
    public void ModelGetsPortGroupsAndNextSteps_NotFortyUnsortedLeads()
    {
        var leads = CloudLeadRanking.Rank(Enumerable.Range(0, 40).Select(index => JsonSerializer.SerializeToElement(new
        {
            port = index % 2 == 0 ? 53 : 443,
            cve = $"CVE-2026-{index + 1000}",
            name = "DNS HTTP",
            source = "NVD",
        })));
        var observation = new ReActObservation
        {
            ToolName = "vuln_scan",
            Success = true,
            Result = JsonSerializer.Serialize(new { cloudCandidates = leads, cloudCandidateCount = 40, cloudCandidateGroups = CloudLeadRanking.Group(leads) }),
        };
        var formatted = AgentObservationFormatter.ForModel(observation);
        using var doc = JsonDocument.Parse(formatted);
        Assert.False(doc.RootElement.TryGetProperty("cloudCandidates", out _));
        Assert.Equal(40, doc.RootElement.GetProperty("cloudCandidateCount").GetInt32());
        Assert.Equal(2, doc.RootElement.GetProperty("cloudCandidateGroups").GetArrayLength());
        Assert.Contains("固件", formatted);
        Assert.Contains("cloudCandidates", observation.Result);
    }

    [Fact]
    public void TrustAndDnsEvidenceRemainReadableAndUnmodified()
    {
        var json = JsonSerializer.Serialize(new { trustErrors = new[] { "NameMismatch", "PartialChain" }, recursionAssessment = "对当前扫描源开放递归" });
        var formatted = AgentObservationFormatter.ForModel(new() { ToolName = "ssl_check", Result = json });
        Assert.Contains("NameMismatch", formatted);
        Assert.Contains("PartialChain", formatted);
        Assert.Contains("对当前扫描源开放递归", formatted);
    }
}
