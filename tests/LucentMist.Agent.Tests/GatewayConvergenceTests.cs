using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class GatewayConvergenceTests
{
    internal const string Ports = """{"target":"192.168.2.1","openPorts":[53,80,443]}""";
    internal const string Vulns = """{"target":"192.168.2.1","openPorts":[53,80,443],"totalFindings":0,"sourcesConsulted":["内置库","NVD"],"noMatchReason":"版本未知，无法确认具体 CVE","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"},{"port":80,"reason":"服务器未公开版本"},{"port":443,"reason":"服务器未公开版本"}]}""";
    internal const string Tls = """{"target":"192.168.2.1","port":443,"isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain"]}""";

    internal static Mock<ITool> Tool(string name, Func<ToolArguments, ToolResult> result)
    {
        var tool = new Mock<ITool>();
        tool.SetupGet(t => t.Name).Returns(name);
        tool.SetupGet(t => t.Description).Returns(name);
        tool.SetupGet(t => t.Parameters).Returns([]);
        tool.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((ToolArguments args, CancellationToken _) => result(args));
        return tool;
    }

    [Fact]
    public async Task UnknownVersionsAndConflictingDns_ConvergeOnFirstQualifiedFinal()
    {
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(t => t.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "port_scan", ActionInput = """{"target":"192.168.2.1"}""" })
            .ReturnsAsync(new ReActStep { Action = "vuln_scan", ActionInput = """{"target":"192.168.2.1"}""" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "暴露53/80/443；HTTPS信任失败。版本未知，查询固件；DNS需复测。" });
        var registry = new ToolRegistry()
            .Register(Tool("port_scan", _ => ToolResult.Ok(Ports, TimeSpan.Zero)).Object)
            .Register(Tool("vuln_scan", _ => ToolResult.Ok(Vulns, TimeSpan.Zero)).Object)
            .Register(Tool("ssl_check", _ => ToolResult.Ok(Tls, TimeSpan.Zero)).Object)
            .Register(Tool("service_identify", args => ToolResult.Ok(JsonSerializer.Serialize(new
            {
                target = "192.168.2.1",
                port = args.GetInt("port"),
                dnsSecurity = args.GetInt("port") == 53 ? new { recursionAvailable = false, recursionAssessment = "未观察到对当前扫描源开放递归" } : null,
            }), TimeSpan.Zero)).Object);
        var result = await new ReActEngine(llm.Object, registry, "prompt").RunAsync("分析 192.168.2.1 的安全风险");
        Assert.True(result.Success);
        Assert.DoesNotContain(result.Observations, o => o.ToolName == "analysis_completeness");
        Assert.Contains("不一致", result.Answer);
        Assert.Contains("PartialChain", result.Answer);
        Assert.Contains("固件", result.Answer);
        Assert.Contains("53/80/443", result.Answer);
        Assert.Equal(3, result.ThoughtLog.Count);
    }

    [Fact]
    public void FailedTlsIsLimitation_NotAnotherMandatoryAttempt()
    {
        var observations = new List<ReActObservation>
        {
            new() { ToolName = "vuln_scan", Success = true, Result = Vulns },
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.2.1","port":53,"dnsSecurity":{}}""" },
            new() { ToolName = "ssl_check", Success = false, Input = """{"target":"192.168.2.1","port":"443"}""", Result = "TLS 握手失败" },
        };
        Assert.Empty(SecurityAnalysisEvidence.FindIncompleteChecks("分析网关", observations, includeFailedAttempts: false));
        Assert.NotEmpty(SecurityAnalysisEvidence.FindIncompleteChecks("分析网关", observations));
        var answer = SecurityAnalysisEvidence.LimitedAssessment("分析网关", observations);
        Assert.Contains("有限安全评估", answer);
        Assert.Contains("53, 80, 443", answer);
        Assert.Contains("TLS 握手失败", answer);
        Assert.Contains("下一步", answer);
        Assert.DoesNotContain("analysis_completeness", answer);
    }

    [Fact]
    public void MissingPortDiscoveryRemainsBlocking()
    {
        Assert.Contains("尚未检查目标端口暴露面", SecurityAnalysisEvidence.FindIncompleteChecks("分析 192.168.2.1 安全", []));
    }
}
