using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class ConclusionEvidenceTests
{
    [Fact]
    public void CompactTlsFactsMustStillDiscloseExpiration()
    {
        var observation = new ReActObservation
        {
            ToolName = "ssl_check",
            Success = true,
            Result = """{"target":"192.168.2.1","isExpired":true,"trustErrors":["NotTimeValid"]}"""
        };
        var answer = SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "HTTPS 信任错误 NotTimeValid，中间人风险需关注。", [observation]);
        Assert.Contains("证书已过期", answer);
    }

    [Theory]
    [InlineData("DNS 放大比 2.1，单点风险较低", true)]
    [InlineData("DNS 放大比 2.1，属中低水平", true)]
    [InlineData("DNS 放大比 2.1，不能据此说明风险较低", false)]
    [InlineData("DNS 本次响应/请求比 2.1，不是攻击风险评级；公网可达性未验证", false)]
    public void RealGateway_ResponseRatioCannotBecomeAnUnsupportedRiskGrade(string answer, bool conflict)
    {
        var observation = new ReActObservation
        {
            ToolName = "service_identify",
            Success = true,
            Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":false}}"""
        };
        Assert.Equal(conflict, SecurityAnalysisEvidence.FindConclusionConflicts(answer, [observation]).Count > 0);
    }

    [Fact]
    public void RealGateway_MissingTlsEvidenceAddsOnlyCompactFacts_NotTheEntireDnAndRepeatedAdvice()
    {
        var answer = SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "先核对HTTPS身份。", [new()
        {
            ToolName = "ssl_check", Success = true, Result = IssuedTls,
        }]);
        Assert.Contains("NameMismatch", answer);
        Assert.Contains("CN=ZTE-ROOT-CA", answer);
        Assert.Contains("中间人风险", answer);
        Assert.DoesNotContain("O=ZTE", answer);
        Assert.True(answer.Length < 350);
    }

    [Theory]
    [InlineData("未发现 22/RDP 等远程管理端口", true)]
    [InlineData("本次未开放 RDP", true)]
    [InlineData("RDP 未检查，不能断言未开放 RDP", false)]
    [InlineData("仅检查 TCP 1-1000；3389 不在扫描范围内", false)]
    public void RealGateway_UnscannedRdpCannotBeClaimedAbsent(string answer, bool conflict)
    {
        var observation = new ReActObservation
        {
            ToolName = "port_scan",
            Success = true,
            Result = """{"target":"192.168.2.1","scannedPortRange":"1-1000","openPorts":[53,80,443]}""",
        };
        Assert.Equal(conflict, SecurityAnalysisEvidence.FindConclusionConflicts(answer, [observation]).Count > 0);
    }

    [Fact]
    public void RealGateway_CompleteTlsAndDnsSummaryIsNotAppendedAgain()
    {
        var answer = "HTTPS 信任失败：NameMismatch、PartialChain；主体与签发者不同，不能称为自签，可能增加中间人风险，不等于遭攻击；应核对完整证书链。" +
                     "DNS 未观察到对当前扫描源开放递归；公网可达性未验证。";
        var observations = new ReActObservation[]
        {
            new() { ToolName = "ssl_check", Success = true, Result = IssuedTls },
            new() { ToolName = "service_identify", Success = true,
                Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAssessment":"未观察到对当前扫描源开放递归"}}""" },
        };
        Assert.Equal(answer, SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", answer, observations));
    }

    [Fact]
    public void RealGateway_VulnerabilityFooterKeepsEvidenceWithoutRepeatingEveryPortAndLead()
    {
        var observation = new ReActObservation { ToolName = "vuln_scan", Success = true, Result = GatewayConvergenceTests.Vulns };
        var answer = SecurityAnalysisEvidence.WithVerifiedFacts("分析网关", "53/80/443 暴露；先核对固件。", [observation]);
        Assert.Contains("内置库 + NVD", answer);
        Assert.Contains("版本未知", answer);
        Assert.DoesNotContain("端口 80 判断", answer);
        Assert.True(answer.Length < 350);
    }

    [Fact]
    public void UnknownDnsResponseIsNotAContradictoryNegativeObservation()
    {
        var observations = new ReActObservation[]
        {
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":false,"recursionStatus":"unknown"}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":true,"recursionStatus":"observed"}}""" },
        };
        Assert.Empty(SecurityAnalysisEvidence.DnsDisagreementNote(observations));
        Assert.NotEmpty(SecurityAnalysisEvidence.FindConclusionConflicts("DNS 未开放递归", observations));
    }
    private const string Tls = """{"target":"192.168.2.1","port":443,"isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain","RevocationStatusUnknown"]}""";
    private const string IssuedTls = """{"target":"192.168.2.1","port":443,"subject":"CN=192.168.1.1, O=ZTE","issuer":"CN=ZTE-ROOT-CA, O=ZTE","isTrusted":false,"isExpired":false,"trustErrors":["NameMismatch","PartialChain"]}""";

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
    public void RealGateway_CorrectParagraphsAreNotRejectedBySentenceOrNegationMatching()
    {
        var observations = new ReActObservation[]
        {
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":false}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.2.1","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"}]}""" },
            new() { ToolName = "ssl_check", Success = true, Result = IssuedTls },
        };
        Assert.Empty(SecurityAnalysisEvidence.FindConclusionConflicts(
            "53/DNS：DNS 服务，版本未公开。不同探测结果不一致：一次观察到递归，另一次未观察到。\n" +
            "HTTPS 信任失败，证书非自签（主体与签发者不同），不能证明根证书可信，存在身份校验风险。", observations));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void RealModel_EmptyFinalIsAContractFailureNotACompletedAnswer(string answer)
    {
        var raw = System.Text.Json.JsonSerializer.Serialize(new { thought = "done", action = "final_answer", action_input = answer });
        Assert.Equal("invalid_response", OpenAIProvider.ParseResponse(raw).Action);
    }

    [Theory]
    [InlineData("HTTPS 身份/信任风险，建议访问管理页时忽略浏览器告警需谨慎对待。", true)]
    [InlineData("HTTPS 信任失败，可忽略非关键校验（仅限内网）。", true)]
    [InlineData("HTTPS 信任失败，不要直接忽略浏览器证书告警，先核对身份。", false)]
    public void RealGateway_TrustFailureMustNotRecommendBypassingVerification(string answer, bool conflict)
    {
        Assert.Equal(conflict, SecurityAnalysisEvidence.FindConclusionConflicts(answer,
            [new() { ToolName = "ssl_check", Success = true, Result = Tls }]).Count > 0);
        Assert.Contains("不要通过忽略", AgentObservationFormatter.ForModel(new()
        {
            ToolName = "ssl_check",
            Success = true,
            Result = Tls,
        }));
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
            .ReturnsAsync(new ReActStep { Action = "ssl_check", ActionInput = "{\"target\":\"192.168.2.1\"}" })
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
            .ReturnsAsync(ToolResult.Ok("""{"primaryIp":"192.168.2.9"}""", TimeSpan.Zero));
        var llm = new Mock<ILLMProvider>();
        llm.SetupSequence(item => item.ReActAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "192.168.12.1" })
            .ReturnsAsync(new ReActStep { Action = "get_my_ip", ActionInput = "{}" })
            .ReturnsAsync(new ReActStep { Action = "final_answer", ActionInput = "192.168.2.9" });
        var result = await new ReActEngine(llm.Object, new ToolRegistry().Register(tool.Object), "prompt").RunAsync("看看我的ip");
        Assert.Equal("192.168.2.9", result.Answer);
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

    [Fact]
    public void InconsistentDnsObservationsAreExplicit_NotCherryPickedAsSafe()
    {
        var observations = new ReActObservation[]
        {
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":false}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.2.1","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"}]}""" },
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
            new() { ToolName = "service_identify", Success = true, Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":false}}""" },
            new() { ToolName = "vuln_scan", Success = true, Result = """{"target":"192.168.2.1","checkedServices":[{"port":53,"reason":"对当前扫描源开放递归"}]}""" },
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
            Result = """{"target":"192.168.2.1","dnsSecurity":{"recursionAvailable":true}}""",
        }]));
    }
}
