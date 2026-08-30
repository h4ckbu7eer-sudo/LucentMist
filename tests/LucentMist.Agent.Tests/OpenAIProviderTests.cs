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

    private sealed class CapturingHandler : HttpMessageHandler
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
                    "{\"choices\":[{\"message\":{\"content\":\"answer\"}}]}",
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
