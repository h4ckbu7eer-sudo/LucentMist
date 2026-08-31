using LucentMist.Agent;
using LucentMist.Agent.LLM;
using LucentMist.Core.Compliance;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace LucentMist.Agent.Tests;

public class ReActEngineTests
{
    private static ToolRegistry CreateRegistry() =>
        new ToolRegistry()
            .Register(new PingScanTool(NullLogger<PingScanTool>.Instance))
            .Register(new PortScanTool(NullLogger<PortScanTool>.Instance));

    private static Mock<ILLMProvider> CreateMockLLM(params ReActStep[] steps)
    {
        var mock = new Mock<ILLMProvider>();
        mock.Setup(m => m.Name).Returns("MockLLM");
        var sequence = mock.SetupSequence(m => m.ReActAsync(
            It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<List<ReActObservation>>(), It.IsAny<string>(),
            It.IsAny<CancellationToken>()));
        foreach (var step in steps)
            sequence = sequence.ReturnsAsync(step);
        return mock;
    }

    // ========================================
    // ReActResult 构造
    // ========================================
    [Fact]
    public void ReActResult_Ok_IsSuccess()
    {
        var r = ReActResult.Ok("答案", ["思考1"], []);
        Assert.True(r.Success);
        Assert.Equal("答案", r.Answer);
    }

    [Fact]
    public void ReActResult_Fail_HasError()
    {
        var r = ReActResult.Fail("出错了", [], []);
        Assert.False(r.Success);
        Assert.Equal("出错了", r.Error);
    }

    // ========================================
    // ReActStep 判断
    // ========================================
    [Fact]
    public void ReActStep_FinalAnswer_IsFinal()
    {
        var step = new ReActStep { Action = "final_answer", ActionInput = "结论" };
        Assert.True(step.IsFinal);
    }

    [Fact]
    public void ReActStep_ToolCall_NotFinal()
    {
        var step = new ReActStep { Action = "port_scan", ActionInput = "{}" };
        Assert.False(step.IsFinal);
    }

    // ========================================
    // ToolRegistry 注册与查询
    // ========================================
    [Fact]
    public void Registry_Register_IncreasesCount()
    {
        var reg = new ToolRegistry();
        Assert.Equal(0, reg.Count);

        reg.Register(new PortScanTool(NullLogger<PortScanTool>.Instance));
        Assert.Equal(1, reg.Count);
    }

    [Fact]
    public void Registry_Get_ReturnsCorrectTool()
    {
        var reg = CreateRegistry();
        var tool = reg.Get("ping_scan");
        Assert.NotNull(tool);
        Assert.Equal("ping_scan", tool.Name);
    }

    [Fact]
    public void Registry_Get_Nonexistent_ReturnsNull()
    {
        var reg = CreateRegistry();
        Assert.Null(reg.Get("nonexistent_tool"));
    }

    [Fact]
    public void Registry_ListAll_ReturnsAllTools()
    {
        var reg = CreateRegistry();
        var all = reg.ListAll().ToList();
        Assert.Equal(2, all.Count);
    }

    [Fact]
    public void Registry_ExportForLLM_ContainsToolNames()
    {
        var reg = CreateRegistry();
        var exp = reg.ExportForLLM();
        Assert.Contains("ping_scan", exp);
        Assert.Contains("port_scan", exp);
    }

    // ========================================
    // LLMProviderFactory
    // ========================================
    [Fact]
    public void Factory_Ollama_CreatesOllamaProvider()
    {
        var provider = LLMProviderFactory.Create("ollama", "qwen2.5:7b", "http://localhost:11434");
        Assert.Equal("Ollama", provider.Name);
    }

    [Fact]
    public void Factory_Claude_CreatesClaudeProvider()
    {
        var provider = LLMProviderFactory.Create("claude", "claude-sonnet-4-6", "http://x", "sk-test");
        Assert.Equal("Claude", provider.Name);
    }

    [Fact]
    public void Factory_DeepSeek_CreatesOpenAICompatibleProvider()
    {
        var provider = LLMProviderFactory.Create(
            "deepseek",
            "deepseek-chat",
            "https://api.deepseek.com/v1",
            "test-key");

        Assert.IsType<OpenAIProvider>(provider);
        Assert.Equal("deepseek-chat", LLMProviderDefaults.ModelFor("deepseek"));
    }

    [Fact]
    public void Factory_Unknown_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            LLMProviderFactory.Create("unknown", "x", "http://x"));
    }

    // ========================================
    // ReActObservation
    // ========================================
    [Fact]
    public void ReActObservation_Defaults()
    {
        var obs = new ReActObservation();
        Assert.Equal(0, obs.Step);
        Assert.False(obs.Success);
    }

    // ========================================
    // ReActEngine 基本构造
    // ========================================
    [Fact]
    public void Engine_Constructor_SetsMaxRounds()
    {
        var llm = LLMProviderFactory.Create("ollama", "llama3.1:8b", "http://localhost:11434");
        var engine = new ReActEngine(llm, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance)
        { MaxRounds = 7 };

        Assert.Equal(7, engine.MaxRounds);
    }

    // ========================================
    // ReActEngine.RunAsync — 循环逻辑
    // ========================================

    [Fact]
    public async Task RunAsync_FinalAnswer_ReturnsSuccessWithAnswer()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "信息足够", Action = "final_answer", ActionInput = "分析完成" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("扫描网络");

        Assert.True(result.Success);
        Assert.Equal("分析完成", result.Answer);
        Assert.Single(result.ThoughtLog);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task RunAsync_ToolCallThenFinal_ExecutesToolAndAnswers()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描本地", Action = "ping_scan", ActionInput = @"{""target"":""127.0.0.1""}" },
            new ReActStep { Thought = "完成", Action = "final_answer", ActionInput = "扫描完毕" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("扫描");

        Assert.True(result.Success);
        Assert.Equal("扫描完毕", result.Answer);
        Assert.Equal(2, result.ThoughtLog.Count);
        Assert.Single(result.Observations);
        Assert.True(result.Observations[0].Success);
        Assert.Equal("ping_scan", result.Observations[0].ToolName);
    }

    [Fact]
    public async Task RunAsync_LLMThrowsException_ReturnsFailure()
    {
        var mockLLM = new Mock<ILLMProvider>();
        mockLLM.Setup(m => m.Name).Returns("MockLLM");
        mockLLM.Setup(m => m.ReActAsync(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<List<ReActObservation>>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("连接失败"));

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("查询");

        Assert.False(result.Success);
        Assert.Contains("LLM 调用失败", result.Error);
    }

    [Fact]
    public async Task RunAsync_CanceledToken_PropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var engine = new ReActEngine(
            LLMProviderFactory.Create("ollama", "llama3.1:8b", "http://localhost:11434"),
            CreateRegistry(),
            "prompt",
            NullLogger<ReActEngine>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            engine.RunAsync("test", cts.Token));
    }

    [Fact]
    public async Task RunAsync_UnknownTool_ObservesFailure()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "试试", Action = "nonexistent_tool", ActionInput = "{}" },
            new ReActStep { Thought = "失败", Action = "final_answer", ActionInput = "工具不存在" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success); // 第二轮 final_answer 成功
        Assert.Equal(2, result.ThoughtLog.Count);
        Assert.Single(result.Observations);
        Assert.False(result.Observations[0].Success);
        Assert.Contains("未知工具", result.Observations[0].Result);
    }

    [Fact]
    public async Task RunAsync_MaxRoundsReached_ForceTerminates()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描A", Action = "ping_scan", ActionInput = @"{""target"":""192.168.1.1""}" },
            new ReActStep { Thought = "扫描B", Action = "ping_scan", ActionInput = @"{""target"":""10.0.0.1""}" },
            new ReActStep { Thought = "还要扫", Action = "ping_scan", ActionInput = @"{""target"":""172.16.0.1""}" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance)
        { MaxRounds = 2 };

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Equal(2, result.ThoughtLog.Count);
        Assert.Equal(2, result.Observations.Count);
        Assert.Contains("分析结果如下", result.Answer);
    }

    [Fact]
    public async Task RunAsync_DuplicateOperation_DetectsAndTerminates()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描", Action = "ping_scan", ActionInput = @"{""target"":""127.0.0.1""}" },
            new ReActStep { Thought = "再扫描", Action = "ping_scan", ActionInput = @"{""target"":""127.0.0.1""}" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance)
        { MaxRounds = 5 };

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Equal(2, result.ThoughtLog.Count);
        Assert.Single(result.Observations); // 只执行了第一次
        Assert.Contains("分析结果如下", result.Answer);
    }

    [Fact]
    public async Task RunAsync_NonAdjacentEquivalentOperation_IsNotExecutedAgain()
    {
        var first = new Mock<ITool>();
        first.Setup(t => t.Name).Returns("first");
        first.Setup(t => t.Description).Returns("first");
        first.Setup(t => t.Parameters).Returns([]);
        first.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("{}", TimeSpan.Zero));

        var second = new Mock<ITool>();
        second.Setup(t => t.Name).Returns("second");
        second.Setup(t => t.Description).Returns("second");
        second.Setup(t => t.Parameters).Returns([]);
        second.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("{}", TimeSpan.Zero));

        var llm = CreateMockLLM(
            new ReActStep { Action = "first", ActionInput = "{\"b\":2,\"a\":\"1\"}" },
            new ReActStep { Action = "second", ActionInput = "{}" },
            new ReActStep { Action = "first", ActionInput = "{\"a\":1,\"b\":\"2\"}" });
        var engine = new ReActEngine(
            llm.Object,
            new ToolRegistry().Register(first.Object).Register(second.Object),
            "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Equal(2, result.Observations.Count);
        first.Verify(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RunAsync_ToolFailure_ExposesErrorToNextRound()
    {
        var tool = new Mock<ITool>();
        tool.Setup(t => t.Name).Returns("failing");
        tool.Setup(t => t.Description).Returns("failing");
        tool.Setup(t => t.Parameters).Returns([]);
        tool.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Fail("连接超时", TimeSpan.Zero));
        var llm = CreateMockLLM(
            new ReActStep { Action = "failing", ActionInput = "{}" },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(
            llm.Object,
            new ToolRegistry().Register(tool.Object),
            "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.Equal("连接超时", Assert.Single(result.Observations).Result);
    }

    [Fact]
    public async Task RunAsync_ToolThrowsException_ObservesFailure()
    {
        // Register a tool that throws
        var registry = new ToolRegistry();
        var mockTool = new Mock<ITool>();
        mockTool.Setup(t => t.Name).Returns("broken_tool");
        mockTool.Setup(t => t.Description).Returns("会崩溃的工具");
        mockTool.Setup(t => t.Parameters).Returns([]);
        mockTool.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("工具内部错误"));
        registry.Register(mockTool.Object);

        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "试试", Action = "broken_tool", ActionInput = "{}" },
            new ReActStep { Thought = "补救", Action = "final_answer", ActionInput = "工具坏了" }
        );

        var engine = new ReActEngine(mockLLM.Object, registry, "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Single(result.Observations);
        Assert.False(result.Observations[0].Success);
        Assert.Contains("工具内部错误", result.Observations[0].Result);
    }

    [Fact]
    public async Task RunAsync_ForbiddenTarget_IsRejectedBeforeToolExecution()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep
            {
                Thought = "尝试访问云元数据",
                Action = "port_scan",
                ActionInput = @"{""target"":""169.254.169.254"",""ports"":""80""}",
            },
            new ReActStep
            {
                Thought = "被阻止",
                Action = "final_answer",
                ActionInput = "安全策略已阻止",
            });

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Single(result.Observations);
        Assert.False(result.Observations[0].Success);
        Assert.Contains("安全策略拒绝", result.Observations[0].Result);
    }

    [Fact]
    public async Task RunAsync_PublicTargetWithoutAllowList_IsRejected()
    {
        var llm = CreateMockLLM(
            new ReActStep
            {
                Action = "safe_network_tool",
                ActionInput = "{\"target\":\"8.8.8.8\"}",
            },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(
            llm.Object,
            new ToolRegistry().Register(new SuccessfulNetworkTool()),
            "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        var observation = Assert.Single(result.Observations);
        Assert.False(observation.Success);
        Assert.Contains("LMIST_ALLOWED_TARGETS", observation.Result);
    }

    [Fact]
    public async Task RunAsync_PublicTargetInAllowList_IsExecuted()
    {
        var previous = Environment.GetEnvironmentVariable("LMIST_ALLOWED_TARGETS");
        Environment.SetEnvironmentVariable("LMIST_ALLOWED_TARGETS", "8.8.8.8");
        try
        {
            var llm = CreateMockLLM(
                new ReActStep
                {
                    Action = "safe_network_tool",
                    ActionInput = "{\"target\":\"8.8.8.8\"}",
                },
                new ReActStep { Action = "final_answer", ActionInput = "done" });
            var engine = new ReActEngine(
                llm.Object,
                new ToolRegistry().Register(new SuccessfulNetworkTool()),
                "prompt",
                NullLogger<ReActEngine>.Instance);

            var result = await engine.RunAsync("test");

            Assert.True(result.Success);
            Assert.True(Assert.Single(result.Observations).Success);
        }
        finally
        {
            Environment.SetEnvironmentVariable("LMIST_ALLOWED_TARGETS", previous);
        }
    }

    [Fact]
    public async Task RunAsync_NonNetworkTargetParameter_IsNotDnsValidated()
    {
        var tool = new Mock<ITool>();
        tool.Setup(t => t.Name).Returns("record_lookup");
        tool.Setup(t => t.Description).Returns("lookup record by id");
        tool.Setup(t => t.Parameters).Returns([]);
        tool.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("{}", TimeSpan.Zero));
        var llm = CreateMockLLM(
            new ReActStep
            {
                Action = "record_lookup",
                ActionInput = "{\"target\":\"host-record-42\"}"
            },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(
            llm.Object,
            new ToolRegistry().Register(tool.Object),
            "prompt",
            NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(Assert.Single(result.Observations).Success);
        tool.Verify(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RunAsync_EmptyThoughtLog_Initially()
    {
        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "直接回答", Action = "final_answer", ActionInput = "OK" }
        );

        var engine = new ReActEngine(mockLLM.Object, CreateRegistry(), "prompt",
            NullLogger<ReActEngine>.Instance);

        // ThoughtLog 初始为空
        Assert.Empty(engine.ThoughtLog);
        Assert.Empty(engine.Observations);

        await engine.RunAsync("test");

        Assert.Single(engine.ThoughtLog);
    }

    // ========================================
    // 自动服务识别
    // ========================================

    [Fact]
    public async Task RunAsync_PortScanSuccess_TriggersAutoServiceIdentify()
    {
        // Mock port_scan 返回开放端口
        var mockPortScan = new Mock<ITool>();
        mockPortScan.Setup(t => t.Name).Returns("port_scan");
        mockPortScan.Setup(t => t.Description).Returns("scan ports");
        mockPortScan.Setup(t => t.Parameters).Returns([]);
        mockPortScan.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                @"{""target"":""192.168.1.1"",""totalScanned"":100,""openPorts"":[80,443],""scanDuration"":""1s""}",
                TimeSpan.FromMilliseconds(1)));

        // Mock service_identify
        var mockSvcIdentify = new Mock<ITool>();
        mockSvcIdentify.Setup(t => t.Name).Returns("service_identify");
        mockSvcIdentify.Setup(t => t.Description).Returns("identify service");
        mockSvcIdentify.Setup(t => t.Parameters).Returns([]);
        mockSvcIdentify.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                @"{""target"":""192.168.1.1"",""port"":80,""serviceName"":""http"",""identified"":true}",
                TimeSpan.FromMilliseconds(1)));

        var registry = new ToolRegistry()
            .Register(mockPortScan.Object)
            .Register(mockSvcIdentify.Object);

        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描端口", Action = "port_scan", ActionInput = @"{""target"":""192.168.1.1""}" },
            new ReActStep { Thought = "完成", Action = "final_answer", ActionInput = "分析完毕" }
        );

        var engine = new ReActEngine(mockLLM.Object, registry, "prompt",
            NullLogger<ReActEngine>.Instance)
        { MaxRounds = 3 };

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        // port_scan + 2 个 service_identify = 3 observations
        Assert.Equal(3, result.Observations.Count);
        Assert.Equal("port_scan", result.Observations[0].ToolName);
        Assert.Equal("service_identify", result.Observations[1].ToolName);
        Assert.Equal("service_identify", result.Observations[2].ToolName);
        Assert.Equal(3, engine.ObservationsForRound(1).Count);
    }

    [Fact]
    public async Task RunAsync_Port443_TriggersAutomaticTlsAssessment()
    {
        var portScan = new Mock<ITool>();
        portScan.SetupGet(tool => tool.Name).Returns("port_scan");
        portScan.SetupGet(tool => tool.Description).Returns("scan");
        portScan.SetupGet(tool => tool.Parameters).Returns([]);
        portScan.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"openPorts\":[443]}",
                TimeSpan.Zero));

        var service = new Mock<ITool>();
        service.SetupGet(tool => tool.Name).Returns("service_identify");
        service.SetupGet(tool => tool.Description).Returns("identify");
        service.SetupGet(tool => tool.Parameters).Returns([]);
        service.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("{\"target\":\"192.168.1.1\",\"port\":443}", TimeSpan.Zero));

        var ssl = new Mock<ITool>();
        ssl.SetupGet(tool => tool.Name).Returns("ssl_check");
        ssl.SetupGet(tool => tool.Description).Returns("tls");
        ssl.SetupGet(tool => tool.Parameters).Returns([]);
        ssl.Setup(tool => tool.ExecuteAsync(
                It.Is<ToolArguments>(args => args["target"] == "192.168.1.1" && args["port"] == "443"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok("{\"target\":\"192.168.1.1\",\"port\":443,\"isExpired\":false}", TimeSpan.Zero));

        var registry = new ToolRegistry().Register(portScan.Object).Register(service.Object).Register(ssl.Object);
        var llm = CreateMockLLM(
            new ReActStep { Action = "port_scan", ActionInput = "{\"target\":\"192.168.1.1\"}" },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(llm.Object, registry, "prompt", NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.Contains(result.Observations, item => item.ToolName == "ssl_check" && item.Success);
        ssl.VerifyAll();
    }

    [Theory]
    [InlineData("{\"target\":\"192.168.1.1\"}")]
    [InlineData("{\"target\":\"192.168.1.1\",\"open_ports\":\"53\"}")]
    public async Task RunAsync_PortScan_PassesEveryActualOpenPortToVulnerabilityScan(string vulnerabilityInput)
    {
        var portScan = new Mock<ITool>();
        portScan.SetupGet(tool => tool.Name).Returns("port_scan");
        portScan.SetupGet(tool => tool.Description).Returns("scan");
        portScan.SetupGet(tool => tool.Parameters).Returns([]);
        portScan.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"openPorts\":[53,80,443]}",
                TimeSpan.Zero));

        var vulnerabilities = new Mock<ITool>();
        vulnerabilities.SetupGet(tool => tool.Name).Returns("vuln_scan");
        vulnerabilities.SetupGet(tool => tool.Description).Returns("vulnerabilities");
        vulnerabilities.SetupGet(tool => tool.Parameters).Returns([]);
        vulnerabilities.Setup(tool => tool.ExecuteAsync(
                It.Is<ToolArguments>(args =>
                    args["target"] == "192.168.1.1" &&
                    args["open_ports"] == "53,80,443"),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"checkedServices\":[{\"port\":53},{\"port\":80},{\"port\":443}]}",
                TimeSpan.Zero));

        var registry = new ToolRegistry().Register(portScan.Object).Register(vulnerabilities.Object);
        var llm = CreateMockLLM(
            new ReActStep { Action = "port_scan", ActionInput = "{\"target\":\"192.168.1.1\"}" },
            new ReActStep { Action = "vuln_scan", ActionInput = vulnerabilityInput },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(llm.Object, registry, "prompt", NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.Contains(result.Observations, item => item.ToolName == "vuln_scan" && item.Success);
        vulnerabilities.VerifyAll();
    }

    [Fact]
    public async Task RunAsync_FailedTlsCheck_CannotBeFinalizedAsSafe()
    {
        var portScan = new Mock<ITool>();
        portScan.SetupGet(tool => tool.Name).Returns("port_scan");
        portScan.SetupGet(tool => tool.Description).Returns("scan");
        portScan.SetupGet(tool => tool.Parameters).Returns([]);
        portScan.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"openPorts\":[443]}",
                TimeSpan.Zero));

        var ssl = new Mock<ITool>();
        ssl.SetupGet(tool => tool.Name).Returns("ssl_check");
        ssl.SetupGet(tool => tool.Description).Returns("tls");
        ssl.SetupGet(tool => tool.Parameters).Returns([]);
        ssl.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Fail("TLS 握手失败", TimeSpan.Zero));

        var vulnerabilities = new Mock<ITool>();
        vulnerabilities.SetupGet(tool => tool.Name).Returns("vuln_scan");
        vulnerabilities.SetupGet(tool => tool.Description).Returns("vulnerabilities");
        vulnerabilities.SetupGet(tool => tool.Parameters).Returns([]);
        vulnerabilities.Setup(tool => tool.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"openPorts\":[443],\"totalFindings\":0," +
                "\"sourcesConsulted\":[\"内置库\"],\"noMatchReason\":\"HTTPS 版本未知\"," +
                "\"checkedServices\":[{\"port\":443,\"reason\":\"版本未知，无法确认漏洞\"}]}",
                TimeSpan.Zero));

        var registry = new ToolRegistry()
            .Register(portScan.Object)
            .Register(ssl.Object)
            .Register(vulnerabilities.Object);
        var llm = CreateMockLLM(
            new ReActStep { Action = "port_scan", ActionInput = "{\"target\":\"192.168.1.1\"}" },
            new ReActStep { Action = "vuln_scan", ActionInput = "{\"target\":\"192.168.1.1\"}" },
            new ReActStep { Action = "final_answer", ActionInput = "已确认安全" },
            new ReActStep { Action = "final_answer", ActionInput = "已确认安全" },
            new ReActStep { Action = "final_answer", ActionInput = "已确认安全" });
        var engine = new ReActEngine(llm.Object, registry, "prompt", NullLogger<ReActEngine>.Instance)
        {
            MaxRounds = 5,
        };

        var result = await engine.RunAsync("分析 192.168.1.1 的安全风险");

        Assert.True(result.Success);
        Assert.Contains("TLS 握手失败", result.Answer);
        Assert.Contains("未确认", result.Answer);
        Assert.NotEqual("已确认安全", result.Answer);
        Assert.Equal(2, result.Observations.Count(item => item.ToolName == "analysis_completeness"));
    }

    [Fact]
    public void SummarizeObservations_VulnerabilityResultShowsSourcesAndReasons()
    {
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "vuln_scan",
                Input = "{\"target\":\"192.168.1.1\"}",
                Success = true,
                Result = "{\"target\":\"192.168.1.1\",\"totalFindings\":0," +
                         "\"sourcesConsulted\":[\"内置库\",\"NVD\"]," +
                         "\"noMatchReason\":\"服务版本未知，无法确认漏洞状态\"," +
                         "\"checkedServices\":[{\"port\":443,\"reason\":\"版本未知，无法确认漏洞\"}]}"
            }
        };

        var summary = ReActEngine.SummarizeObservations(observations);

        Assert.Contains("数据来源: 内置库 + NVD", summary);
        Assert.Contains("判断依据: 服务版本未知，无法确认漏洞状态", summary);
        Assert.Contains("端口 443 判断: 版本未知，无法确认漏洞", summary);
        Assert.DoesNotContain("来源: 未知", summary);
    }

    [Fact]
    public void SummarizeObservations_RetrySuccessSupersedesEarlierFailure()
    {
        const string input = "{\"target\":\"192.168.1.1\",\"port\":443}";
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "ssl_check",
                Input = input,
                Result = "必须指定目标",
                Success = false,
            },
            new()
            {
                ToolName = "ssl_check",
                Input = input,
                Result = "{\"target\":\"192.168.1.1\",\"port\":443,\"isTrusted\":true,\"isExpired\":false}",
                Success = true,
            },
        };

        var summary = ReActEngine.SummarizeObservations(observations);

        Assert.Contains("证书有效且信任校验通过", summary);
        Assert.DoesNotContain("必须指定目标", summary);
    }

    [Fact]
    public void SummarizeObservations_VulnerabilityFindingIncludesCveCvssSourceAndFix()
    {
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "vuln_scan",
                Input = "{\"target\":\"192.168.1.10\"}",
                Success = true,
                Result = "{\"target\":\"192.168.1.10\",\"totalFindings\":1," +
                         "\"sourcesConsulted\":[\"内置库\",\"NVD\"]," +
                         "\"findings\":[{\"cve\":\"CVE-2023-38408\",\"name\":\"OpenSSH RCE\"," +
                         "\"cvss\":7.5,\"source\":\"内置库\",\"fix\":\"升级到 9.3p2 或更高版本\"}]}"
            }
        };

        var summary = ReActEngine.SummarizeObservations(observations);

        Assert.Contains("CVE-2023-38408 OpenSSH RCE", summary);
        Assert.Contains("CVSS 7.5", summary);
        Assert.Contains("来源 内置库", summary);
        Assert.Contains("升级到 9.3p2", summary);
    }

    [Fact]
    public void SecurityCompleteness_RequiresDnsAssessmentForOpenPort53()
    {
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "port_scan",
                Input = "{\"target\":\"192.168.1.1\"}",
                Success = true,
                Result = "{\"target\":\"192.168.1.1\",\"openPorts\":[53,80,443]}"
            },
            new()
            {
                ToolName = "vuln_scan",
                Input = "{\"target\":\"192.168.1.1\"}",
                Success = true,
                Result = "{\"target\":\"192.168.1.1\",\"openPorts\":[53,80,443]," +
                         "\"checkedServices\":[{\"port\":53},{\"port\":80},{\"port\":443}]}"
            },
            new()
            {
                ToolName = "ssl_check",
                Input = "{\"target\":\"192.168.1.1\",\"port\":443}",
                Success = true,
                Result = "{\"target\":\"192.168.1.1\",\"port\":443,\"isTrusted\":true,\"isExpired\":false}"
            },
        };

        var incomplete = SecurityAnalysisEvidence.FindIncompleteChecks(
            "分析 192.168.1.1 的安全风险",
            observations);

        Assert.Single(incomplete);
        Assert.Contains("DNS 版本/递归检查", incomplete[0]);

        observations.Add(new ReActObservation
        {
            ToolName = "service_identify",
            Input = "{\"target\":\"192.168.1.1\",\"port\":53}",
            Success = true,
            Result = "{\"target\":\"192.168.1.1\",\"port\":53," +
                     "\"dnsSecurity\":{\"recursionAvailable\":false}}"
        });

        Assert.Empty(SecurityAnalysisEvidence.FindIncompleteChecks(
            "分析 192.168.1.1 的安全风险",
            observations));
    }

    [Fact]
    public async Task RunAsync_ArgumentFailure_RepairsAliasesAndRetriesOnce()
    {
        var tool = new AliasRepairTool();
        var registry = new ToolRegistry().Register(tool);
        var llm = CreateMockLLM(
            new ReActStep { Action = tool.Name, ActionInput = "{\"host\":\"127.0.0.1\",\"ssl_port\":443}" },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(llm.Object, registry, "prompt", NullLogger<ReActEngine>.Instance);

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Equal(2, tool.CallCount);
        Assert.Contains(result.Observations, item => item.ToolName == tool.Name && item.Success);
    }

    [Fact]
    public void PromoteNetworkTargetAlias_ExtractsHostBeforePolicyValidation()
    {
        var args = new ToolArguments { ["url"] = "https://router.example:8443/status" };

        ReActEngine.PromoteNetworkTargetAlias(args);

        Assert.Equal("router.example", args["target"]);
    }

    [Fact]
    public void SummarizeObservations_ListsEveryDeviceWithoutEllipsis()
    {
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "ping_scan",
                Input = "{\"target\":\"192.168.1.0/24\"}",
                Success = true,
                Result = "{\"alive\":3,\"total\":254,\"deviceDetails\":[" +
                         "{\"ip\":\"192.168.1.1\",\"name\":\"router.local\",\"vendor\":\"Vendor A\",\"model\":\"未知\"}," +
                         "{\"ip\":\"192.168.1.2\",\"name\":\"nas.local\",\"vendor\":\"Vendor B\",\"model\":\"未知\"}," +
                         "{\"ip\":\"192.168.1.3\",\"name\":\"tv.local\",\"vendor\":\"Vendor C\",\"model\":\"未知\"}]}"
            }
        };

        var summary = ReActEngine.SummarizeObservations(observations);

        Assert.Contains("192.168.1.1", summary);
        Assert.Contains("192.168.1.2", summary);
        Assert.Contains("192.168.1.3", summary);
        Assert.DoesNotContain("...", summary);
    }

    [Fact]
    public void SummarizeObservations_LocalIpUsesPrimaryWithoutListingVirtualPeers()
    {
        var observations = new List<ReActObservation>
        {
            new()
            {
                ToolName = "get_my_ip",
                Input = "{}",
                Success = true,
                Result = "{\"primaryIp\":\"192.168.2.9\",\"primaryInterface\":\"WLAN 2\"," +
                         "\"virtualInterfaceCount\":2,\"interfaces\":[" +
                         "{\"name\":\"VMnet8\",\"ip\":\"192.168.12.1\",\"isVirtual\":true}]}"
            }
        };

        var summary = ReActEngine.SummarizeObservations(observations);
        Assert.Contains("本机主 IPv4: 192.168.2.9（接口: WLAN 2）", summary);
        Assert.Contains("另有 2 个虚拟网卡", summary);
        Assert.DoesNotContain("192.168.12.1", summary);
    }

    [Fact]
    public async Task RunAsync_PortScanNoOpenPorts_NoAutoIdentify()
    {
        var mockPortScan = new Mock<ITool>();
        mockPortScan.Setup(t => t.Name).Returns("port_scan");
        mockPortScan.Setup(t => t.Description).Returns("scan ports");
        mockPortScan.Setup(t => t.Parameters).Returns([]);
        mockPortScan.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                @"{""target"":""192.168.1.1"",""totalScanned"":100,""openPorts"":[],""scanDuration"":""1s""}",
                TimeSpan.FromMilliseconds(1)));

        var registry = new ToolRegistry().Register(mockPortScan.Object);

        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描", Action = "port_scan", ActionInput = @"{""target"":""192.168.1.1""}" },
            new ReActStep { Thought = "无端口", Action = "final_answer", ActionInput = "没有开放端口" }
        );

        var engine = new ReActEngine(mockLLM.Object, registry, "prompt",
            NullLogger<ReActEngine>.Instance)
        { MaxRounds = 3 };

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Single(result.Observations); // 只有 port_scan
    }

    [Fact]
    public async Task RunAsync_PortScanManyPorts_AutoIdentifyIsCapped()
    {
        var openPorts = string.Join(",", Enumerable.Range(1, 25));
        var mockPortScan = new Mock<ITool>();
        mockPortScan.Setup(t => t.Name).Returns("port_scan");
        mockPortScan.Setup(t => t.Description).Returns("scan ports");
        mockPortScan.Setup(t => t.Parameters).Returns([]);
        mockPortScan.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                $"{{\"target\":\"192.168.1.1\",\"totalScanned\":25,\"openPorts\":[{openPorts}]}}",
                TimeSpan.FromMilliseconds(1)));

        var mockSvcIdentify = new Mock<ITool>();
        mockSvcIdentify.Setup(t => t.Name).Returns("service_identify");
        mockSvcIdentify.Setup(t => t.Description).Returns("identify service");
        mockSvcIdentify.Setup(t => t.Parameters).Returns([]);
        mockSvcIdentify.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ToolResult.Ok(
                "{\"target\":\"192.168.1.1\",\"port\":80,\"serviceName\":\"http\",\"identified\":true}",
                TimeSpan.FromMilliseconds(1)));

        var registry = new ToolRegistry()
            .Register(mockPortScan.Object)
            .Register(mockSvcIdentify.Object);

        var mockLLM = CreateMockLLM(
            new ReActStep { Thought = "扫描端口", Action = "port_scan", ActionInput = @"{""target"":""192.168.1.1""}" },
            new ReActStep { Thought = "完成", Action = "final_answer", ActionInput = "分析完毕" }
        );

        var engine = new ReActEngine(mockLLM.Object, registry, "prompt",
            NullLogger<ReActEngine>.Instance)
        {
            MaxRounds = 3,
            MaxAutoIdentifyPorts = 20
        };

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Equal(21, result.Observations.Count); // 1 port_scan + 20 service_identify
    }

    [Fact]
    public async Task RunAsync_NetworkTool_WritesBoundedLifecycleAudit()
    {
        var sink = new CapturingAuditSink();
        var registry = new ToolRegistry().Register(new SuccessfulNetworkTool());
        var llm = CreateMockLLM(
            new ReActStep
            {
                Action = "safe_network_tool",
                ActionInput = "{\"target\":\"192.168.1.25\"}"
            },
            new ReActStep { Action = "final_answer", ActionInput = "done" });
        var engine = new ReActEngine(
            llm.Object,
            registry,
            "prompt",
            NullLogger<ReActEngine>.Instance,
            sink,
            "web-agent");

        var result = await engine.RunAsync("test");

        Assert.True(result.Success);
        Assert.Collection(
            sink.Events,
            item =>
            {
                Assert.Equal("queued", item.Status);
                Assert.Equal("web-agent", item.Initiator);
                Assert.Equal("192.168.1.25", item.Target);
            },
            item =>
            {
                Assert.Equal("completed", item.Status);
                Assert.DoesNotContain("sensitive-result", item.Summary);
            });
        Assert.Equal(sink.Events[0].EventId, sink.Events[1].EventId);
    }

    private sealed class SuccessfulNetworkTool : INetworkTargetTool
    {
        public string Name => "safe_network_tool";
        public string Description => "test";
        public ToolParameter[] Parameters => [];

        public Task<ToolResult> ExecuteAsync(
            ToolArguments args,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(ToolResult.Ok("sensitive-result", TimeSpan.Zero));
    }

    private sealed class AliasRepairTool : ITool
    {
        public int CallCount { get; private set; }
        public string Name => "alias_repair";
        public string Description => "test";
        public ToolParameter[] Parameters =>
        [
            new() { Name = "target", Type = "string", Required = true },
            new() { Name = "port", Type = "integer", Required = true },
        ];

        public Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(args.ContainsKey("target") && args.ContainsKey("port")
                ? ToolResult.Ok("{}", TimeSpan.Zero)
                : ToolResult.Fail("目标和端口参数必填", TimeSpan.Zero));
        }
    }

    private sealed class CapturingAuditSink : INetworkAuditSink
    {
        public List<NetworkAuditEvent> Events { get; } = [];

        public Task RecordAsync(
            NetworkAuditEvent auditEvent,
            CancellationToken ct = default)
        {
            Events.Add(auditEvent);
            return Task.CompletedTask;
        }
    }
}
