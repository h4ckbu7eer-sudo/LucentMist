using LucentMist.Core.Networking;

namespace LucentMist.Scanning.Tests;

public class TargetGuardTests
{
    [Theory]
    [InlineData("127.0.0.1", TargetKind.IpAddress)]
    [InlineData("10.0.0.0/24", TargetKind.Cidr)]
    [InlineData("example.com", TargetKind.Hostname)]
    [InlineData("host-name", TargetKind.Hostname)]
    public void ValidateSyntax_AcceptsSupportedTargets(string target, TargetKind kind)
    {
        var result = TargetGuard.ValidateSyntax(target);

        Assert.True(result.IsAllowed);
        Assert.Equal(kind, result.Kind);
        Assert.Equal("ALLOWED", result.Code);
    }

    [Theory]
    [InlineData("", "TARGET_REQUIRED")]
    [InlineData(" example.com", "TARGET_WHITESPACE")]
    [InlineData("host_name", "INVALID_HOSTNAME")]
    [InlineData("http://example.com", "INVALID_CIDR")]
    [InlineData("2001:db8::1", "IPV6_NOT_SUPPORTED")]
    [InlineData("10.0.0.0/7", "INVALID_CIDR")]
    [InlineData("10.0.0.0/33", "INVALID_CIDR")]
    [InlineData("169.254.169.254", "FORBIDDEN_ADDRESS")]
    [InlineData("100.64.0.0/10", "FORBIDDEN_NETWORK")]
    [InlineData("169.253.0.0/15", "FORBIDDEN_NETWORK")]
    [InlineData("224.0.0.0/8", "FORBIDDEN_NETWORK")]
    public void ValidateSyntax_RejectsUnsafeOrMalformedTargets(string target, string code)
    {
        var result = TargetGuard.ValidateSyntax(target);

        Assert.False(result.IsAllowed);
        Assert.Equal(code, result.Code);
    }

    [Fact]
    public async Task ValidateAsync_ResolvesLocalhostAndReturnsFrozenAddresses()
    {
        var result = await TargetGuard.ValidateAsync("localhost");

        Assert.True(result.IsAllowed);
        Assert.Equal(TargetKind.Hostname, result.Kind);
        Assert.NotEmpty(result.ResolvedAddresses);
        Assert.All(result.ResolvedAddresses, address => Assert.False(string.IsNullOrWhiteSpace(address)));
    }

    [Fact]
    public async Task ValidateAsync_PreservesCancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => TargetGuard.ValidateAsync("example.com", cts.Token));
    }
}
