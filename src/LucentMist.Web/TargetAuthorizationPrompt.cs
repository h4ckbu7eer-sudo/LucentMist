using Microsoft.JSInterop;

namespace LucentMist.Web;

public interface ITargetAuthorizationPrompt
{
    ValueTask<bool> ConfirmPublicTargetAsync(string target, CancellationToken ct = default);
}

public sealed class BrowserTargetAuthorizationPrompt(IJSRuntime js) : ITargetAuthorizationPrompt
{
    public ValueTask<bool> ConfirmPublicTargetAsync(string target, CancellationToken ct = default) =>
        js.InvokeAsync<bool>(
            "confirm",
            ct,
            $"目标 {target} 位于公网。你确认拥有扫描该目标的授权吗？");
}

internal sealed class DenyTargetAuthorizationPrompt : ITargetAuthorizationPrompt
{
    public static DenyTargetAuthorizationPrompt Instance { get; } = new();

    public ValueTask<bool> ConfirmPublicTargetAsync(string target, CancellationToken ct = default) =>
        ValueTask.FromResult(false);
}
