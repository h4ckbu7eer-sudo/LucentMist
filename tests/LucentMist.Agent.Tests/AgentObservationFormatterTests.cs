using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Tools.Security;

namespace LucentMist.Agent.Tests;

public class AgentObservationFormatterTests
{
    [Fact]
    public void DnsModelViewHasOneAssessment_RawConflictingSamplesRemainInSavedEvidence()
    {
        var observation = new ReActObservation
        {
            ToolName = "vuln_scan",
            Success = true,
            Result = """{"dnsSecurity":{"recursionStatus":"unknown","recursionAssessment":"DNS 递归配置未确认","recursionSamples":["RA=False","RA=True"],"recursionAdvertised":true}}""",
        };
        var view = AgentObservationFormatter.ForModel(observation);
        Assert.Contains("递归配置未确认", view);
        Assert.DoesNotContain("RA=", view);
        Assert.DoesNotContain("recursionAdvertised", view);
        Assert.Contains("RA=False", observation.Result);
        Assert.Contains("RA=True", observation.Result);
    }

    [Theory]
    [InlineData("服务版本均未公开（HTTP 无 Server 头、DNS版本未知）", true)]
    [InlineData("所有服务版本都未公开", true)]
    [InlineData("不能断言服务版本均未公开；HTTP 未披露版本，DNS 查询无响应。", false)]
    [InlineData("HTTP 未公开版本；DNS 版本未知，无法判断是否隐藏。", false)]
    [InlineData("不能说 DNS 版本未公开。", false)]
    public void DnsNonResponseDoesNotProveBlanketVersionNondisclosure(string answer, bool conflict)
    {
        var observation = new ReActObservation { ToolName = "vuln_scan", Success = true, Result = """{"dnsSecurity":{"versionAssessment":"DNS 版本查询无有效响应，无法判断是否公开版本"}}""" };
        Assert.Equal(conflict, SecurityAnalysisEvidence.FindConclusionConflicts(answer, [observation]).Count > 0);
    }

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
        Assert.Empty(doc.RootElement.GetProperty("cloudCandidateGroups").EnumerateArray().SelectMany(group => group.GetProperty("leads").EnumerateArray()));
        Assert.Contains("固件", formatted);
        Assert.Contains("cloudCandidates", observation.Result);
        Assert.Equal(40, JsonDocument.Parse(observation.Result).RootElement.GetProperty("cloudCandidates").GetArrayLength());
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
