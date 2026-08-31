using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class ConclusionEvidenceTests
{
    private const string Tls = """{"target":"192.168.99.1","port":443,"isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain","RevocationStatusUnknown"]}""";
    private const string IssuedTls = """{"target":"192.168.99.1","port":443,"subject":"CN=192.168.1.1, O=ZTE","issuer":"CN=ZTE-ROOT-CA, O=ZTE","isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain"]}""";

    [Theory]
    [InlineData("HTTPS 使用 ZTE 自签证书，存在信任风险")]
    [InlineData("HTTPS 信任失败，不能断言自签（此处确为自签根）")]
    public void RealGateway_IssuedLeafCannotBeInventedAsSelfSigned(string answer)
    {
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts(answer,
            [new() { ToolName = "ssl_check", Success = true, Result = IssuedTls }]));
    }

    [Fact]
    public void RealGateway_IssuerEvidenceReachesModelAndFinal()
    {
        var observation = new ReActObservation { ToolName = "ssl_check", Success = true, Result = IssuedTls };
        Assert.Contains("主体与签发者不同", AgentObservationFormatter.ForModel(observation));
        var final = SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "证书信任失败，不能认定为自签证书", [observation]);
        Assert.Contains("主体与签发者不同", final);
        Assert.Contains("CN=ZTE-ROOT-CA", final);
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts(final, [observation]));
    }

    [Fact]
    public async Task RealGateway_WrongSelfSignedConclusionIsRetried()
    {
        var tool = new Mock<ITool>();
        tool.SetupGet(item => item.Name).Returns("ssl_check");
        tool.SetupGet(item => item.Description).Returns("TLS");
        tool.SetupGet(item => item.Parameters).Returns([]);
        tool.Setup(item => item.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(IssuedTls, TimeSpan.Zero));
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(item => item.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "ssl_check", ActionInput = "{\"target\":\"192.168.99.1\"}" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "HTTPS 使用自签证书，存在信任风险" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "HTTPS 信任失败，签发者与主体不同，不能断言为自签证书" });
        var result = await new ReActEngine(llm.Object, new ToolRegistry().Register(tool.Object), "prompt").RunAsync("分析网关风险");
        Assert.Contains(result.Observations, item => item.ToolName == "analysis_completeness");
        Assert.DoesNotContain("HTTPS 使用自签证书", result.Answer);
        Assert.Contains("主体与签发者不同", result.Answer);
    }

    [Fact]
    public async Task InvalidContractIsFedBackInsteadOfDisplayedAsFinal()
    {
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(item => item.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenAIProvider.ParseResponse("broken JSON"))
            .ReturnsAsync(new ReActStep { Thought = "corrected", Action = "final_answer", ActionInput = "correct answer" });
        var result = await new ReActEngine(llm.Object, new ToolRegistry(), "prompt").RunAsync("hello");
        Assert.Equal("correct answer", result.Answer);
        Assert.Contains(result.Observations, item => item.ToolName == "response_contract" && !item.Success);
        Assert.DoesNotContain("broken JSON", result.Answer);
    }

    [Fact]
    public async Task MyIpFinalMustUseCurrentTool_NotJustInjectedSnapshot()
    {
        var tool = new Mock<ITool>();
        tool.SetupGet(item => item.Name).Returns("get_my_ip");
        tool.SetupGet(item => item.Description).Returns("local interfaces");
        tool.SetupGet(item => item.Parameters).Returns([]);
        tool.Setup(item => item.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("""{"primaryIp":"192.168.99.9"}""", TimeSpan.Zero));
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(item => item.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "192.168.12.1" })
            .ReturnsAsync(new ReActStep { Action = "get_my_ip", ActionInput = "{}" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "192.168.99.9" });
        var result = await new ReActEngine(llm.Object, new ToolRegistry().Register(tool.Object), "prompt").RunAsync("看看我的ip");
        Assert.Equal("192.168.99.9", result.Answer);
        Assert.Contains(result.Observations, item => item.ToolName == "get_my_ip" && item.Success);
    }

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
            .ReturnsAsync(new ReActStep { Action = "ssl_check", ActionInput = "{\"target\":\"192.168.99.1\"}" })
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
            Result = """{"target":"192.168.99.1","port":53,"dnsSecurity":{"recursionAvailable":true,"recursionAssessment":"对当前扫描源开放递归"}}""",
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

    [Fact]
    public void InconsistentDnsObservationsAreExplicit_NotCherryPickedAsSafe()
    {
        var observations = new ReActObservation[]
        {
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.99.1","dnsSecurity":{"recursionAvailable":false}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.99.1","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"}]}""" },
        };
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts("未开放递归", observations));
        Assert.Contains("不一致", SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "待核查", observations));
        Assert.Contains("不一致", ReActEngine.SummarizeObservations(observations.ToList()));
    }

    [Fact]
    public void RealWebAnswer_TlsNameMismatchDoesNotAcknowledgeDnsDisagreement()
    {
        var observations = new ReActObservation[]
        {
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.99.1","dnsSecurity":{"recursionAvailable":false}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.99.1","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"}]}""" },
        };
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts(
            "53/DNS：未观察到对当前扫描源开放递归。HTTPS 证书身份与访问网关不一致。", observations));
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts(
            "DNS 探测结果不一致：service_identify 未观察到对当前扫描源开放递归，vuln_scan 观察到递归。不能认定已关闭。", observations));
    }

    [Theory]
    [InlineData("对扫描源开放递归，不能断言公网开放或“未开放递归”。")]
    [InlineData("对扫描源开放递归，不应说成未开放递归。")]
    public void NegatedSafetyClaimsDoNotTriggerFalseConflicts(string answer)
    {
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts(answer, [new()
        {
            ToolName = "service_identify", Success = true,
            Result = """{"target":"192.168.99.1","dnsSecurity":{"recursionAvailable":true}}""",
        }]));
    }
}
