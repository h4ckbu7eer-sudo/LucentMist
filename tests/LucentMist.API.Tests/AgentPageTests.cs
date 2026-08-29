extern alias LucentMistWeb;
using System.Net;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using AgentPage = LucentMistWeb::LucentMist.Web.Components.Pages.Agent;

namespace LucentMist.API.Tests;

public sealed class AgentPageTests
{
    [Fact]
    public async Task DefaultView_ExplainsExperimentalStatusWithoutOpeningChat()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<IHttpClientFactory>(new UnexpectedHttpClientFactory())
            .BuildServiceProvider();
        await using var renderer = new HtmlRenderer(services, NullLoggerFactory.Instance);

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var output = await renderer.RenderComponentAsync<AgentPage>();
            return WebUtility.HtmlDecode(output.ToHtmlString());
        });

        Assert.Contains("实验性功能 — 非专家不建议使用", html);
        Assert.Contains("href=\"/scan\"", html);
        Assert.Contains("href=\"/scan/history\"", html);
        Assert.Contains("我了解限制，启用实验性 Agent", html);
        Assert.DoesNotContain("例如：扫描 127.0.0.1 的端口", html);
        Assert.DoesNotContain(">发送<", html);
    }

    private sealed class UnexpectedHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            throw new InvalidOperationException(
                "The default Agent view must not contact the API before opt-in.");
    }
}
