using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Tools.Security;

namespace LucentMist.Agent.Tests;

public class AgentObservationFormatterTests
{
    [Theory]
    [InlineData("service_identify")]
    [InlineData("vuln_scan")]
    public void DnsNonResponseAndSizeRatioGuidancePrecedesFinalAnswer(string tool)
    {
        var observation = new ReActObservation { ToolName = tool, Success = true, Result = """{"dnsSecurity":{"amplificationRatio":2.1,"versionAssessment":"DNS 版本查询无有效响应，无法判断是否公开版本"}}""" };
        var formatted = AgentObservationFormatter.ForModel(observation);
        Assert.Contains("不能据此称低风险", formatted);
        Assert.Contains("不能说版本被隐藏或未公开", formatted);
        Assert.Contains("2.1", formatted);
        Assert.DoesNotContain("interpretation", observation.Result);
        Assert.Contains(SecurityAnalysisEvidence.FindConclusionConflicts("DNS 版本未公开", [observation]),
            item => item.Contains("无有效响应"));
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts("DNS 版本未知，查询无有效响应，不能断言是否隐藏。", [observation]));
    }

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
        Assert.Equal(5, doc.RootElement.GetProperty("cloudCandidateGroups").EnumerateArray().Sum(group => group.GetProperty("leads").GetArrayLength()));
        Assert.Contains("固件", formatted);
        Assert.Contains("cloudCandidates", observation.Result);
        Assert.Equal(6, JsonDocument.Parse(observation.Result).RootElement.GetProperty("cloudCandidateGroups").EnumerateArray().Sum(group => group.GetProperty("leads").GetArrayLength()));
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
