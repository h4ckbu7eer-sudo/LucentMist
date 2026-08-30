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
    public async Task RunAsync_PublicTarget_IsAllowedWithoutAgentConfirmation()
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
