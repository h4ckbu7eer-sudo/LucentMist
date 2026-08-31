using System.Text.Json;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public class GeneralScopeEvidenceTests
{
    private static ReActObservation Scan(string target, string ports) => new()
    {
        ToolName = "port_scan",
        Success = true,
        Result = JsonSerializer.Serialize(new { target, scannedPortRange = ports, openPorts = Array.Empty<int>() }),
    };

    [Theory]
    [InlineData("127.0.0.1", "80,443", "未发现端口 65001", true)]
    [InlineData("127.0.0.1", "80,443", "未发现端口65001", true)]
    [InlineData("127.0.0.1", "80,443", "未发现65001端口", true)]
    [InlineData("10.8.0.1", "1-1000", "PostgreSQL 未开放", true)]
    [InlineData("172.20.1.7", "1-1000", "port 54321 is closed", true)]
    [InlineData("10.8.0.1", "80,443", "65000端口已关闭", true)]
    [InlineData("10.8.0.1", "1-65535", "未发现65000", false)]
    [InlineData("127.0.0.1", "80,443", "未发现80，65001未检查", false)]
    [InlineData("10.8.0.22", "80,443", "未发现目标 10.8.0.22", false)]
    [InlineData("127.0.0.1", "80,443", "未发现 CVE-2024-65001", false)]
    public void NumericPortsAndCatalogServicesAreNotGatewaySpecific(string target, string range, string answer, bool rejected)
    {
        Assert.Equal(rejected, PortScopeEvidence.FindConflicts(answer, [Scan(target, range)]).Any());
    }

    [Fact]
    public void RepeatedScansUnionRangesOnlyForTheSameTarget()
    {
        var observations = new[] { Scan("10.8.0.1", "80,443"), Scan("10.8.0.1", "65000"), Scan("10.8.0.2", "80") };
        Assert.Empty(PortScopeEvidence.FindConflicts("10.8.0.1 未发现65000", observations));
        Assert.NotEmpty(PortScopeEvidence.FindConflicts("10.8.0.2 未发现65000", observations));
    }

    [Theory]
    [InlineData("0.1")]
    [InlineData("3.7")]
    [InlineData("20")]
    public void DnsRatioIsNeverAnAttackRiskThreshold(string ratio)
    {
        var observation = new ReActObservation
        {
            ToolName = "service_identify",
            Success = true,
            Result = """{"target":"10.8.0.1","dnsSecurity":{"recursionAvailable":false}}"""
        };
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts($"DNS 放大比 {ratio}，风险较低", [observation]));
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts($"DNS 放大比 {ratio}，不能据此断言风险较低", [observation]));
    }
}
