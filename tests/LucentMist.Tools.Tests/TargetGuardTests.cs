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

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.2.3.4", false)]
    [InlineData("172.31.255.1", false)]
    [InlineData("192.168.10.0/24", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("203.0.113.0/24", true)]
    public async Task ValidateAsync_ClassifiesPublicTargets(
        string target,
        bool requiresAuthorization)
    {
        var result = await TargetGuard.ValidateAsync(target, allowedTargets: null);

        Assert.True(result.IsAllowed);
        Assert.Equal(requiresAuthorization, result.RequiresPublicAuthorization);
    }

    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData("203.0.113.10", "203.0.113.0/24")]
    [InlineData("203.0.113.0/25", "203.0.113.0/24")]
    public async Task ValidateAsync_AllowsTargetsInsideConfiguredScope(
        string target,
        string allowedTargets)
    {
        var result = await TargetGuard.ValidateAsync(target, allowedTargets);

        Assert.True(result.IsAllowed);
        Assert.True(result.IsExplicitlyAllowed);
        Assert.False(result.RequiresPublicAuthorization);
    }

    [Theory]
    [InlineData("203.0.113.10", "198.51.100.0/24", "TARGET_OUTSIDE_ALLOWED_SCOPE")]
    [InlineData("203.0.113.0/24", "203.0.113.0/25", "TARGET_OUTSIDE_ALLOWED_SCOPE")]
    [InlineData("10.2.3.4", "not a target", "INVALID_ALLOWED_TARGETS")]
    public async Task ValidateAsync_RejectsTargetsOutsideConfiguredScope(
        string target,
        string allowedTargets,
        string expectedCode)
    {
        var result = await TargetGuard.ValidateAsync(target, allowedTargets);

        Assert.False(result.IsAllowed);
        Assert.Equal(expectedCode, result.Code);
    }

    [Theory]
    [InlineData("10.2.3.4")]
    [InlineData("172.16.10.4")]
    [InlineData("192.168.99.9")]
    [InlineData("127.0.0.1")]
    public async Task ValidateAsync_PrivateTargetsRemainAllowedWithPublicAllowList(string target)
    {
        var result = await TargetGuard.ValidateAsync(target, "203.0.113.0/24");

        Assert.True(result.IsAllowed);
        Assert.False(result.RequiresPublicAuthorization);
    }
}
