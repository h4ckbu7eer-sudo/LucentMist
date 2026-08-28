using LucentMist.Core.Networking;

namespace LucentMist.Tools.Tests;

public class TargetGuardTests
{
    [Theory]
    [InlineData("127.0.0.1", "ipv4")]
    [InlineData("10.0.0.0/24", "cidr")]
    public async Task ValidateAsync_AllowsSupportedTargets(string target, string targetType)
    {
        var result = await TargetGuard.ValidateAsync(target);

        Assert.True(result.IsAllowed);
        Assert.Equal(targetType, result.TargetType);
    }

    [Theory]
    [InlineData("169.254.169.254", "FORBIDDEN_ADDRESS")]
    [InlineData("169.252.0.0/14", "FORBIDDEN_ADDRESS_RANGE")]
    [InlineData("100.0.0.0/9", "FORBIDDEN_ADDRESS_RANGE")]
    [InlineData("host_name", "INVALID_HOSTNAME")]
    [InlineData("::1", "IPV6_NOT_SUPPORTED")]
    public async Task ValidateAsync_RejectsUnsafeOrUnsupportedTargets(string target, string code)
    {
        var result = await TargetGuard.ValidateAsync(target);

        Assert.False(result.IsAllowed);
        Assert.Equal(code, result.Code);
    }

    [Fact]
    public async Task ValidateAsync_CanceledDns_PropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            TargetGuard.ValidateAsync("does-not-exist.example.invalid", cts.Token));
    }
}
