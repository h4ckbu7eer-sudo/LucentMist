using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class GatewayConvergenceTests
{
    internal const string Ports = """{"target":"192.168.99.1","openPorts":[53,80,443]}""";
    internal const string Vulns = """{"target":"192.168.99.1","openPorts":[53,80,443],"totalFindings":0,"sourcesConsulted":["内置库","NVD"],"noMatchReason":"版本未知，无法确认具体 CVE","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"},{"port":80,"reason":"服务器未公开版本"},{"port":443,"reason":"服务器未公开版本"}]}""";
    internal const string Tls = """{"target":"192.168.99.1","port":443,"isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain"]}""";

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
            .ReturnsAsync(new ReActStep { Action = "port_scan", ActionInput = """{"target":"192.168.99.1"}""" })
            .ReturnsAsync(new ReActStep { Action = "vuln_scan", ActionInput = """{"target":"192.168.99.1"}""" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "暴露53/80/443；HTTPS信任失败。版本未知，查询固件；DNS需复测。" });
        var registry = new ToolRegistry()
            .Register(Tool("port_scan", _ => ToolResult.Ok(Ports, TimeSpan.Zero)).Object)
            .Register(Tool("vuln_scan", _ => ToolResult.Ok(Vulns, TimeSpan.Zero)).Object)
            .Register(Tool("ssl_check", _ => ToolResult.Ok(Tls, TimeSpan.Zero)).Object)
            .Register(Tool("service_identify", args => ToolResult.Ok(JsonSerializer.Serialize(new
            {
                target = "192.168.99.1",
                port = args.GetInt("port"),
                dnsSecurity = args.GetInt("port") == 53 ? new { recursionAvailable = false, recursionAssessment = "未观察到对当前扫描源开放递归" } : null,
            }), TimeSpan.Zero)).Object);
        var result = await new ReActEngine(llm.Object, registry, "prompt").RunAsync("分析 192.168.99.1 的安全风险");
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
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.99.1","port":53,"dnsSecurity":{}}""" },
            new() { ToolName = "ssl_check", Success = false, Input = """{"target":"192.168.99.1","port":"443"}""", Result = "TLS 握手失败" },
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
        Assert.Contains("尚未检查目标端口暴露面", SecurityAnalysisEvidence.FindIncompleteChecks("分析 192.168.99.1 安全", []));
    }

    [Fact]
    public void FailedDiscoveryRemainsVisibleWithoutDemandingEndlessRetry()
    {
        var observations = new[] { new ReActObservation { ToolName = "port_scan", Success = false, Result = "网络不可达" } };
        Assert.NotEmpty(SecurityAnalysisEvidence.FindIncompleteChecks("分析 192.168.99.1 安全", observations));
        Assert.Empty(SecurityAnalysisEvidence.FindIncompleteChecks("分析 192.168.99.1 安全", observations, includeFailedAttempts: false));
        Assert.Contains("网络不可达", SecurityAnalysisEvidence.LimitedAssessment("分析 192.168.99.1 安全", observations));
    }

    [Fact]
    public void EmptyTcpAndUnprobeableUdp_ProduceUsefulProtocolSpecificAssessment()
    {
        var observations = new[]
        {
            new ReActObservation { ToolName = "port_scan", Success = true, Result = """{"target":"192.168.99.7","openPorts":[],"scannedPortRange":"1-1000"}""" },
            new ReActObservation { ToolName = "udp_scan", Success = true, Result = """{"target":"192.168.99.7","ports":[{"port":5353,"state":"unprobeable"},{"port":53,"state":"closed"}]}""" },
        };

        var answer = SecurityAnalysisEvidence.LimitedAssessment("分析 192.168.99.7 是否安全", observations);

        Assert.Contains("未观察到开放端口", answer);
        Assert.Contains("unprobeable=5353", answer);
        Assert.DoesNotContain("核对 HTTPS", answer);
        Assert.Contains("当前证据不能推出目标安全", answer);
    }

    [Fact]
    public void DeniedPublicTarget_DoesNotEraseEvidenceCollectedForAnotherTarget()
    {
        var observations = new[]
        {
            new ReActObservation
            {
                ToolName = "port_scan",
                Success = true,
                Result = """{"target":"192.168.99.1","openPorts":[53,443]}""",
            },
            new ReActObservation
            {
                ToolName = "vuln_scan",
                Success = false,
                Input = """{"target":"8.8.8.8"}""",
                Result = "公网扫描授权未确认：该公网目标未执行任何网络探测。",
            },
        };

        var answer = SecurityAnalysisEvidence.LimitedAssessment("分析这些目标的安全风险", observations);

        Assert.Contains("192.168.99.1", answer);
        Assert.Contains("53, 443", answer);
        Assert.Contains("授权边界 8.8.8.8", answer);
        Assert.DoesNotContain("目前只有用户输入的目标", answer);
    }
}
