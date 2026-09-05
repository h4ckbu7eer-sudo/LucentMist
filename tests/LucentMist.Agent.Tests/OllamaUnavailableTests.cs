using System.Net;
using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public class OllamaUnavailableTests
{
    [Fact]
    public async Task TagsAvailableButModelMissingIsAlsoRecoverable()
    {
        using var client = new HttpClient(new MissingModelHandler());
        var provider = new OllamaProvider("http://127.0.0.1:11434", "test-model", http: client);
        var error = await Assert.ThrowsAsync<LlmUnavailableException>(() => provider.ReActAsync("prompt", "query", [], "[]"));
        Assert.Contains("ollama list", error.Message);
        Assert.Contains("ollama pull", error.Message);
    }

    private sealed class MissingModelHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(request.RequestUri!.AbsolutePath == "/api/tags" ? HttpStatusCode.OK : HttpStatusCode.NotFound));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnavailableProviderGivesActionableAdviceWithoutRawConnectionDetails(bool refused)
    {
        using var client = new HttpClient(new Handler(refused));
        var provider = new OllamaProvider("http://127.0.0.1:11434", "test-model", http: client);
        var error = await Assert.ThrowsAsync<LlmUnavailableException>(() =>
            provider.ReActAsync("prompt", "query", [], "[]"));
        Assert.Contains("ollama serve", error.Message);
        Assert.Contains("vuln-scan", error.Message);
        Assert.DoesNotContain("private connection detail", error.Message);
    }

    private sealed class Handler(bool refused) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => refused
            ? throw new HttpRequestException("private connection detail")
            : Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }
}
