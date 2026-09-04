extern alias LucentMistWeb;

using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using AppState = LucentMistWeb::LucentMist.Web.AppState;
using ITargetAuthorizationPrompt = LucentMistWeb::LucentMist.Web.ITargetAuthorizationPrompt;
using ScanService = LucentMistWeb::LucentMist.Web.ScanService;

namespace LucentMist.API.Tests;

public sealed class SslWebStateTests
{
    [Fact]
    public void FromToolResult_UntrustedCertificateIsNotRenderedAsValidAndTrusted()
    {
        using var document = JsonDocument.Parse("""
        {
          "target":"192.168.1.1",
          "port":443,
          "isExpired":false,
          "isTrusted":false,
          "daysRemaining":100,
          "notAfter":"2027-01-01T00:00:00+00:00",
          "subject":"CN=router",
          "issuer":"CN=router",
          "thumbprintSha256":"abc",
          "chain":[],
          "trustExplanations":["证书与目标名称不匹配","证书链不完整"]
        }
        """);

        var state = AppState.SslState.FromToolResult(document.RootElement);

        Assert.False(state.Expired);
        Assert.False(state.Trusted);
        Assert.Equal("有效期内但不受信任", state.StatusLabel);
        Assert.Contains("证书链不完整", state.TrustExplanations);
    }

    [Fact]
    public async Task DirectWebTool_PublicTargetRequiresExplicitAuthorization()
    {
        var prompt = new StubAuthorizationPrompt(false);
        var service = new ScanService(NullLoggerFactory.Instance, prompt);

        var rejection = await service.AuthorizeTargetAsync("1.1.1.1", CancellationToken.None);

        Assert.NotNull(rejection);
        Assert.False(rejection.Success);
        Assert.Contains("未确认公网目标", rejection.Error);
        Assert.Equal(1, prompt.Calls);
    }

    private sealed class StubAuthorizationPrompt(bool answer) : ITargetAuthorizationPrompt
    {
        public int Calls { get; private set; }

        public ValueTask<bool> ConfirmPublicTargetAsync(string target, CancellationToken ct = default)
        {
            Calls++;
            return ValueTask.FromResult(answer);
        }
    }
}
