using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class NmapEnhancerTests
{
    [Fact]
    public async Task TimeoutActuallyKillsChildRatherThanAwaitingItsOutputForever()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var result = await NmapEnhancer.RunProcessAsync(SleepProcess(), TimeSpan.FromMilliseconds(300), default);
        Assert.Null(result);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(6));
    }

    [Fact]
    public async Task CallerCancellationPropagatesAndStopsChild()
    {
        using var cts = new CancellationTokenSource(300);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            NmapEnhancer.RunProcessAsync(SleepProcess(), TimeSpan.FromSeconds(10), cts.Token));
    }

    private static System.Diagnostics.ProcessStartInfo SleepProcess()
    {
        var psi = new System.Diagnostics.ProcessStartInfo(OperatingSystem.IsWindows() ? "powershell.exe" : "/bin/sh")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (OperatingSystem.IsWindows())
        {
            psi.ArgumentList.Add("-NoProfile"); psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add("Start-Sleep -Seconds 30");
        }
        else { psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("sleep 30"); }
        return psi;
    }
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("scanme.nmap.org")]
    [InlineData("example.com")]
    public void IsValidTarget_AcceptsIpAndHostname(string target)
    {
        Assert.True(NmapEnhancer.IsValidTarget(target));
    }

    [Theory]
    [InlineData("")]
    [InlineData("example.com; rm -rf /")]
    [InlineData("-oX /tmp/evil")]
    [InlineData("foo bar")]
    public void IsValidTarget_RejectsUnsafeInput(string target)
    {
        Assert.False(NmapEnhancer.IsValidTarget(target));
    }
}
