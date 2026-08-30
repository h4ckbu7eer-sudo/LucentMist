using LucentMist.CLI;

namespace LucentMist.Tools.Tests;

public sealed class AgentReplTests
{
    [Fact]
    public async Task Repl_EntersRunsMultipleTurnsReusesSessionAndExits()
    {
        using var input = new StringReader("first question\nsecond question\nexit\n");
        using var output = new StringWriter();
        var calls = new List<(string Input, string? SessionId)>();

        var exitCode = await CliApp.RunAgentReplLoopAsync(
            input,
            output,
            (message, sessionId, _) =>
            {
                calls.Add((message, sessionId));
                return Task.FromResult(new CliApp.AgentReplTurnResult(
                    0,
                    sessionId ?? "session-1"));
            });

        Assert.Equal(0, exitCode);
        Assert.Collection(
            calls,
            first =>
            {
                Assert.Equal("first question", first.Input);
                Assert.Null(first.SessionId);
            },
            second =>
            {
                Assert.Equal("second question", second.Input);
                Assert.Equal("session-1", second.SessionId);
            });
        Assert.Contains("交互模式", output.ToString());
        Assert.Equal(3, CountOccurrences(output.ToString(), "agent> "));
    }

    [Fact]
    public async Task Repl_QuitExitsWithoutCallingAgent()
    {
        using var input = new StringReader("quit\n");
        using var output = new StringWriter();
        var calls = 0;

        var exitCode = await CliApp.RunAgentReplLoopAsync(
            input,
            output,
            (_, _, _) =>
            {
                calls++;
                return Task.FromResult(new CliApp.AgentReplTurnResult(0, "unused"));
            });

        Assert.Equal(0, exitCode);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("/exit")]
    [InlineData("/quit")]
    public async Task Repl_SlashExitCommandsExitWithoutCallingAgent(string command)
    {
        using var input = new StringReader($"{command}\n");
        using var output = new StringWriter();
        var calls = 0;

        var exitCode = await CliApp.RunAgentReplLoopAsync(
            input,
            output,
            (_, _, _) =>
            {
                calls++;
                return Task.FromResult(new CliApp.AgentReplTurnResult(0, "unused"));
            });

        Assert.Equal(0, exitCode);
        Assert.Equal(0, calls);
    }

    private static int CountOccurrences(string value, string search) =>
        (value.Length - value.Replace(search, "", StringComparison.Ordinal).Length) / search.Length;
}
