using System.Text.Json;
using LucentMist.CLI;
using Spectre.Console;

namespace LucentMist.Tools.Tests;

public sealed class ScanCommandOptionTests
{
    [Fact]
    public void ShouldRunPing_DefaultsToTrue()
    {
        Assert.True(CliApp.ShouldRunPing(["127.0.0.1", "--ports", "80"]));
    }

    [Fact]
    public void ShouldRunPing_NoPingDisablesDiscoveryStage()
    {
        Assert.False(CliApp.ShouldRunPing(["127.0.0.1", "--ports", "80", "--no-ping"]));
    }

    [Fact]
    public void SubnetDiscoveryTableListsEveryDeviceWithIdentityColumns()
    {
        using var document = JsonDocument.Parse("""
        [{"ip":"192.168.99.1","mac":"00:11:22:33:44:55","vendor":"Vendor A","name":"gateway","model":"R1"},
         {"ip":"192.168.99.9","mac":null,"vendor":"未知","name":"workstation","model":"PC"}]
        """);
        using var output = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            Out = new AnsiConsoleOutput(output),
        });

        console.Write(CliApp.BuildPingDeviceTable(document.RootElement));
        var rendered = output.ToString();

        Assert.Contains("192.168.99.1", rendered);
        Assert.Contains("192.168.99.9", rendered);
        Assert.Contains("在线状态", rendered);
        Assert.Contains("Vendor A", rendered);
        Assert.Contains("R1", rendered);
    }

    [Fact]
    public void DeepSeekWithoutKey_IsRejectedInsteadOfSilentlyFallingBack()
    {
        var error = CliApp.ValidateAgentLlmConfiguration("deepseek", "");

        Assert.Contains("LMIST_LLM_APIKEY 未配置", error);
        Assert.Contains("不会静默回退", error);
        Assert.Null(CliApp.ValidateAgentLlmConfiguration("deepseek", "configured-secret"));
    }

    [Fact]
    public void OllamaConfiguration_IsExplicitAboutLocalRuntimeRequirement()
    {
        var notice = CliApp.AgentProviderNotice("ollama");

        Assert.Contains("本地 Ollama", notice);
        Assert.Contains("ollama serve", notice);
        Assert.Null(CliApp.AgentProviderNotice("deepseek"));
    }
}
