using LucentMist.Agent;
using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Moq;

namespace LucentMist.Agent.Tests;

public class AutomaticOsEvidenceTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SecurityAnalysisAutomaticallyFingerprintsAndPassesSameTargetEvidence(bool osSucceeds)
    {
        var registry = new ToolRegistry();
        var port = Tool("port_scan", ToolResult.Ok("""{"target":"192.168.99.1","openPorts":[53,80,443]}""", TimeSpan.Zero));
        var os = Tool("os_fingerprint", osSucceeds
            ? ToolResult.Ok("""{"target":"192.168.99.1","osFamily":"Linux","confidence":30}""", TimeSpan.Zero)
            : ToolResult.Fail("无法获取 TTL", TimeSpan.Zero));
        var vuln = Tool("vuln_scan", ToolResult.Ok("""{"target":"192.168.99.1","totalFindings":0} """, TimeSpan.Zero));
        registry.Register(port.Object).Register(os.Object).Register(vuln.Object);
        var model = new Mock<ILLMProvider>();
        model.SetupSequence(m => m.ReActAsync(It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<List<ReActObservation>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ReActStep { Action = "port_scan", ActionInput = """{"target":"192.168.99.1"}""" })
            .ReturnsAsync(new ReActStep { Action = "vuln_scan", ActionInput = """{"target":"192.168.99.1"}""" });
        var engine = new ReActEngine(model.Object, registry, "test") { MaxRounds = 2 };
        var result = await engine.RunAsync("分析 192.168.99.1 的安全风险");
        Assert.True(result.Success);
        os.Verify(t => t.ExecuteAsync(It.Is<ToolArguments>(args => args["target"] == "192.168.99.1" &&
            args["open_ports"] == "53,80,443"), It.IsAny<CancellationToken>()), Times.Once);
        vuln.Verify(t => t.ExecuteAsync(It.Is<ToolArguments>(args => args.ContainsKey("os_evidence") == osSucceeds &&
            args["open_ports"] == "53,80,443"), It.IsAny<CancellationToken>()), Times.Once);
        Assert.Single(result.Observations, o => o.ToolName == "os_fingerprint");
        Assert.DoesNotContain(result.Observations, o => o.ToolName == "analysis_completeness");
    }

    [Fact]
    public void DefaultRegistryAlreadyContainsOsFingerprint()
    {
        var registry = ToolRegistryFactory.CreateDefault(Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
        Assert.NotNull(registry.Get("os_fingerprint"));
    }

    private static Mock<ITool> Tool(string name, ToolResult result)
    {
        var mock = new Mock<ITool>();
        mock.SetupGet(t => t.Name).Returns(name);
        mock.SetupGet(t => t.Description).Returns(name);
        mock.SetupGet(t => t.Parameters).Returns([]);
        mock.Setup(t => t.ExecuteAsync(It.IsAny<ToolArguments>(), It.IsAny<CancellationToken>())).ReturnsAsync(result);
        return mock;
    }
}
