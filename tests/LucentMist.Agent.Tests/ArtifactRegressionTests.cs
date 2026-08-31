using System.Text.Json;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public class ArtifactRegressionTests
{
    private static ReActObservation Certificate(string expiry) => new()
    {
        ToolName = "ssl_check",
        Success = true,
        Result = JsonSerializer.Serialize(new { target = "10.9.0.7", notAfterUtc = expiry, isTrusted = true, isExpired = false }),
    };

    [Theory]
    [InlineData("2031-07-10T01:32:15Z", "证书2026 年到期", true)]
    [InlineData("2042-02-09T00:00:00Z", "证书2031年到期", true)]
    [InlineData("2031-07-10T01:32:15Z", "证书2031年到期", false)]
    [InlineData("2031-07-10T01:32:15Z", "expires on 2026-07-10", true)]
    [InlineData("2031-07-10T01:32:15Z", "证书不是2026年到期，而是2031年到期", false)]
    [InlineData("2031-07-10T01:32:15Z", "2026年的CVE不能证明证书过期", false)]
    public void ExpirationYearUsesObservedCertificateNotCurrentYear(string expiry, string answer, bool conflict)
    {
        Assert.Equal(conflict, SecurityAnalysisEvidence.FindConclusionConflicts(answer, [Certificate(expiry)]).Count > 0);
    }

    [Fact]
    public void ExactExpirationIsVisibleToModelAndUser()
    {
        var observation = Certificate("2042-02-09T00:00:00Z");
        Assert.Contains("2042-02-09", AgentObservationFormatter.ForModel(observation));
        Assert.Contains("2042-02-09", SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "评估", [observation]));
    }

    [Theory]
    [InlineData("范围外端口（如22、3389、8080）未检查", true)]
    [InlineData("范围外端口（如3389、8080）未检查", false)]
    [InlineData("22端口未检查", true)]
    [InlineData("UDP端口53未检查", false)]
    [InlineData("端口443的TLS证书未检查", false)]
    public void ScannedPortsCannotBeCalledOutsideScope(string answer, bool conflict)
    {
        var scan = new ReActObservation
        {
            ToolName = "port_scan",
            Success = true,
            Result = """{"target":"10.9.0.7","scannedPortRange":"1-1000","openPorts":[53,80,443]}"""
        };
        Assert.Equal(conflict, PortScopeEvidence.FindConflicts(answer, [scan]).Any());
        Assert.Contains("scopeInterpretation", AgentObservationFormatter.ForModel(scan));
    }
}
