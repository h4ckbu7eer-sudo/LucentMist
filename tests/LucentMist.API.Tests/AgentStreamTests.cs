using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Scanning;
using LucentMist.Tools;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace LucentMist.API.Tests;

public class AgentStreamTests
{
    [Fact]
    public async Task SseDeliversThoughtAndObservationBeforeFinalModelCallCompletes()
    {
        var llm = new ControlledProvider();
        await using var factory = CreateFactory(llm);
        using var client = factory.CreateClient();
        using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agent/chat")
        {
            Content = JsonContent.Create(new { message = "STREAM" }),
        };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct.Token);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(ct.Token));
        var events = new List<string>();
        while (await reader.ReadLineAsync(ct.Token) is { } line)
        {
            if (line.StartsWith("event:")) events.Add(line);
            if (line == "event: observation") break;
        }
        Assert.Contains("event: session", events);
        Assert.Contains("event: thought", events);
        Assert.Contains("event: action", events);
        Assert.False(llm.Release.Task.IsCompleted);
        llm.Release.TrySetResult();
        Assert.Contains("event: message", await reader.ReadToEndAsync(ct.Token));
    }

    [Fact]
    public async Task SessionIdRoundTripActuallySuppliesPreviousMessagesToModel()
    {
        var llm = new ControlledProvider();
        await using var factory = CreateFactory(llm);
        using var client = factory.CreateClient();
        using var first = await client.PostAsJsonAsync("/api/v1/agent/chat", new { message = "我的主 IP 为 192.168.99.9，网关 192.168.99.1" });
        var body = await first.Content.ReadAsStringAsync();
        var sessionLine = body.Split('\n').First(line => line.StartsWith("data:"));
        using var session = JsonDocument.Parse(sessionLine[5..]);
        var id = session.RootElement.GetProperty("sessionId").GetString();
        using var second = await client.PostAsJsonAsync("/api/v1/agent/chat", new { message = "那个网关是什么地址", sessionId = id });
        Assert.True(second.IsSuccessStatusCode);
        var actual = llm.Queries.Last();
        Assert.Contains("192.168.99.9", actual);
        Assert.Contains("192.168.99.1", actual);
        Assert.Contains("当前用户问题：\n那个网关是什么地址", actual);
        using var unrelated = await client.PostAsJsonAsync("/api/v1/agent/chat", new { message = "new session" });
        Assert.DoesNotContain("192.168.99.9", llm.Queries.Last());
    }

    private static WebApplicationFactory<Program> CreateFactory(ControlledProvider llm)
    {
        var db = Path.Combine(Path.GetTempPath(), $"lmist-agent-stream-{Guid.NewGuid():N}.db");
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<ILLMProvider>();
            services.AddSingleton<ILLMProvider>(llm);
            services.RemoveAll<ToolRegistry>();
            services.AddSingleton(new ToolRegistry().Register(new LocalTool()));
            services.RemoveAll<ScanStore>();
            services.AddSingleton(new ScanStore(db));
            services.RemoveAll<AgentSessionStore>();
            services.AddSingleton(new AgentSessionStore(db));
        }));
    }

    private sealed class LocalTool : ITool
    {
        public string Name => "local_test";
        public string Description => "No network IO";
        public ToolParameter[] Parameters => [];
        public Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken ct = default) =>
            Task.FromResult(ToolResult.Ok("{\"ok\":true}", TimeSpan.Zero));
    }

    private sealed class ControlledProvider : ILLMProvider
    {
        public string Name => "Test";
        public ConcurrentQueue<string> Queries { get; } = new();
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<string> ChatAsync(string prompt, List<ChatMessage> history, CancellationToken ct = default) => throw new NotSupportedException();
        public async Task<ReActStep> ReActAsync(string prompt, string query, List<ReActObservation> observations, string definitions, CancellationToken ct = default)
        {
            Queries.Enqueue(query);
            if (query == "STREAM")
            {
                if (observations.Count == 0) return new() { Thought = "running", Action = "local_test", ActionInput = "{}" };
                await Release.Task.WaitAsync(ct);
            }
            return new() { Thought = "done", Action = "final_answer", ActionInput = "记住了" };
        }
    }
}
