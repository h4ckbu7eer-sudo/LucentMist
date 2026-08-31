using System.Net;
using System.Text;
using System.Text.Json;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public sealed class OpenAIProviderTests
{
    [Fact]
    public async Task ChatAsync_UsesOpenAIContractWithoutPuttingApiKeyInBody()
    {
        var handler = new CapturingHandler();
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.deepseek.com/v1/"),
        };
        var provider = new OpenAIProvider(
            "test-secret-key",
            "deepseek-chat",
            http: http);

        var reply = await provider.ChatAsync(
            "system",
            [new ChatMessage("user", "hello")]);

        Assert.Equal("answer", reply);
        Assert.Equal(
            new Uri("https://api.deepseek.com/v1/chat/completions"),
            handler.RequestUri);
        Assert.Equal("Bearer", handler.AuthorizationScheme);
        Assert.Equal("test-secret-key", handler.AuthorizationParameter);
        using var body = JsonDocument.Parse(handler.Body!);
        Assert.Equal("deepseek-chat", body.RootElement.GetProperty("model").GetString());
        Assert.Equal("hello", body.RootElement.GetProperty("messages")[1]
            .GetProperty("content").GetString());
        Assert.DoesNotContain("test-secret-key", handler.Body);
        provider.Dispose();
    }

    [Fact]
    public async Task ReActRequestsJsonModeAndObjectArguments()
    {
        var handler = new CapturingHandler("""{"thought":"probe","action":"ssl_check","action_input":{"target":"192.168.99.1","port":443}}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.deepseek.com/v1/") };
        var provider = new OpenAIProvider("fake-test-secret", "deepseek-chat", http: http);
        var step = await provider.ReActAsync("Return JSON", "check", [], "- ssl_check: TLS");
        using var body = JsonDocument.Parse(handler.Body!);
        Assert.Equal("json_object", body.RootElement.GetProperty("response_format").GetProperty("type").GetString());
        Assert.Equal(0, body.RootElement.GetProperty("temperature").GetInt32());
        var prompt = body.RootElement.GetProperty("messages")[1].GetProperty("content").GetString();
        Assert.Contains("每个字段只出现一次", prompt);
        Assert.Contains("工具调用时必须是 JSON 对象", prompt);
        Assert.Equal("ssl_check", step.Action);
        Assert.Contains("192.168.99.1", step.ActionInput);
        Assert.DoesNotContain("fake-test-secret", handler.Body);
    }

    [Theory]
    [InlineData("{\"thought\":\"done\",\"action\":\"final_answer\",\"action_input\":\"first\nsecond\"}")]
    [InlineData("{\"thought\":\"done\",\"action\":\"ssl_check\",\"action_input\":[443]}")]
    [InlineData("")]
    [InlineData("""{"thought":"done","action":"final_answer","action_input":"first","action_input":"second"}""")]
    [InlineData("""{"thought":"probe","action":"ssl_check","action_input":{"target":"first","target":"second"}}""")]
    [InlineData("""{"thought":"probe","action":"ssl_check","action_input":"{\"target\":\"first\",\"target\":\"second\"}"}""")]
    [InlineData("{\"thought\":\"done\",\"action\":\"final_answer\",\"action_input\":\"ok\",\"action\":\"port_scan\"}")]
    [InlineData("{\"thought\":\"done\",\"action\":\"final_answer\",\"action_input\":\"ok\"};")]
    public void InvalidModelOutputIsNotPresentedAsAnAnswer(string raw)
    {
        var parsed = OpenAIProvider.ParseResponse(raw);
        Assert.False(parsed.IsFinal);
        Assert.Equal("invalid_response", parsed.Action);
        Assert.Contains("合法 JSON", parsed.ActionInput);
    }

    private sealed class CapturingHandler(string reply = "answer") : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }
        public string? AuthorizationScheme { get; private set; }
        public string? AuthorizationParameter { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            AuthorizationParameter = request.Headers.Authorization?.Parameter;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { choices = new[] { new { message = new { content = reply } } } }),
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
