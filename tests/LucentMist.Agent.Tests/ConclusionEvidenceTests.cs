using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class ConclusionEvidenceTests
{
    private const string Tls = """{"target":"192.168.2.1","port":443,"isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain","RevocationStatusUnknown"]}""";

    [Fact]
    public async Task TrustErrors_ReachObservationAndFinalEvenWhenModelOmitsThem()
    {
        var tool = new Mock<ITool>();
        tool.SetupGet(item => item.Name).Returns("ssl_check");
        tool.SetupGet(item => item.Description).Returns("TLS");
        tool.SetupGet(item => item.Parameters).Returns([]);
        tool.Setup(item => item.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(Tls, TimeSpan.Zero));
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(item => item.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "ssl_check", ActionInput = "{\"target\":\"192.168.2.1\"}" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "证书未过期，安全" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "证书存在信任问题，应核对身份" });
        var engine = new ReActEngine(llm.Object, new ToolRegistry().Register(tool.Object), "prompt");
        var result = await engine.RunAsync("分析网关安全风险");
        Assert.Contains(result.Observations, item => item.ToolName == "ssl_check" && item.Result.Contains("NameMismatch"));
        Assert.Contains(result.Observations, item => item.ToolName == "analysis_completeness");
        Assert.Contains("HTTPS 信任风险", result.Answer);
        Assert.Contains("PartialChain", result.Answer);
        Assert.Contains("中间人风险", result.Answer);
        Assert.DoesNotContain("证书未过期，安全", result.Answer);
    }

    [Theory]
    [InlineData("DNS 未开放递归，正常")]
    [InlineData("DNS 未对扫描源开放递归")]
    public void ObservedRecursionCannotBeNegated(string answer)
    {
        var observations = new[] { new ReActObservation
        {
            ToolName = "service_identify", Success = true,
            Result = """{"target":"192.168.2.1","port":53,"dnsSecurity":{"recursionAvailable":true,"recursionAssessment":"对当前扫描源开放递归"}}""",
        } };
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts(answer, observations));
        var final = SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "需控制 DNS 暴露面", observations);
        Assert.Contains("对当前扫描源开放递归", final);
        Assert.Contains("未验证公网可达性", final);
    }

    [Fact]
    public void SelfSignedBeingCommonDoesNotMakeTrustFailureSafe()
    {
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts("证书链不受信任，属正常", [new()
        {
            ToolName = "ssl_check", Success = true, Result = Tls,
        }]));
    }
}
