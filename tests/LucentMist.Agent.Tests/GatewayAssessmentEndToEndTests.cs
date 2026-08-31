using System.Text.Json;
using System.Text.Json.Nodes;
using LucentMist.Agent.LLM;
using LucentMist.Tools;
using LucentMist.Tools.Security;
using Moq;
using Xunit.Abstractions;

namespace LucentMist.Agent.Tests;

public class GatewayAssessmentEndToEndTests(ITestOutputHelper output)
{
    [Fact]
    public async Task UnknownGatewayWithFiftyLeadsAndDnsConflict_ProducesBoundedAssessmentAtDeferralLimit()
    {
        var leads = CloudLeadRanking.Rank(Enumerable.Range(0, 50).Select(i => JsonSerializer.SerializeToElement(new
        {
            port = i % 3 == 0 ? 53 : i % 3 == 1 ? 80 : 443,
            cve = i < 10 ? $"CVE-1999-{1000 + i}" : $"CVE-2024-{1000 + i}",
            name = "DNS HTTP keyword fixture (not a real finding)",
            source = "NVD fixture",
            cvss = i < 10 ? 0.0 : 7.5,
            referenceCount = i < 10 ? 1000 : 1,
            versionStatus = "unverified",
        })));
        var data = JsonNode.Parse(GatewayConvergenceTests.Vulns)!.AsObject();
        data["cloudCandidates"] = JsonSerializer.SerializeToNode(leads);
        data["cloudCandidateGroups"] = JsonSerializer.SerializeToNode(CloudLeadRanking.Group(leads));
        data["cloudNextStep"] = CloudLeadRanking.NextStep;
        data["cloudCandidateCount"] = 50;
        var ports = GatewayConvergenceTests.Tool("port_scan", _ => ToolResult.Ok(GatewayConvergenceTests.Ports, TimeSpan.Zero));
        var vulnerability = GatewayConvergenceTests.Tool("vuln_scan", args =>
        {
            Assert.Equal("53,80,443", args.GetOrDefault("open_ports"));
            return ToolResult.Ok(data.ToJsonString(), TimeSpan.Zero);
        });
        var tls = GatewayConvergenceTests.Tool("ssl_check", _ => ToolResult.Ok(GatewayConvergenceTests.Tls, TimeSpan.Zero));
        var service = GatewayConvergenceTests.Tool("service_identify", args => ToolResult.Ok(JsonSerializer.Serialize(new
        {
            target = "192.168.2.1",
            port = args.GetInt("port"),
            dnsSecurity = args.GetInt("port") == 53 ? new { recursionAvailable = false, recursionAssessment = "未观察到对当前扫描源开放递归" } : null,
        }), TimeSpan.Zero));
        var registry = new ToolRegistry().Register(ports.Object).Register(vulnerability.Object).Register(tls.Object).Register(service.Object);
        var llm = new Mock<ILLMProvider>();
        var rounds = 0;
        llm.Setup(m => m.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => ++rounds switch
            {
                1 => new ReActStep { Action = "port_scan", ActionInput = """{"target":"192.168.2.1"}""" },
                2 => new ReActStep { Action = "vuln_scan", ActionInput = """{"target":"192.168.2.1"}""" },
                _ => new ReActStep { Action = "final_answer", ActionInput = "DNS 未开放递归，已确认安全" },
            });
        var engine = new ReActEngine(llm.Object, registry, "simulation") { MaxRounds = 10, MaxCompletionDeferrals = 2 };
        var result = await engine.RunAsync("分析 192.168.2.1 的安全风险");
        Assert.True(result.Success, result.Error);
        Assert.Equal(5, rounds);
        Assert.Contains("有限安全评估", result.Answer);
        Assert.Contains("53, 80, 443", result.Answer);
        Assert.Contains("NameMismatch", result.Answer);
        Assert.Contains("不一致", result.Answer);
        Assert.Contains("版本未知", result.Answer);
        Assert.Contains("下一步", result.Answer);
        Assert.DoesNotContain("CVE-1999", result.Answer);
        Assert.DoesNotContain("analysis_completeness", result.Answer);
        Assert.DoesNotContain("已确认安全", result.Answer);
        Assert.InRange(result.Answer.Length, 1, 5000);
        ports.Verify(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()), Times.Once);
        vulnerability.Verify(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()), Times.Once);
        tls.Verify(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()), Times.Once);
        output.WriteLine($"SIMULATED gateway + scripted model: rounds={rounds}; tool calls: port=1,vuln=1,TLS=1; source leads=50\n{result.Answer}");
    }
}
