using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class NmapEnhancerTests
{
    [Fact]
    public async Task ObservationScope_ReusesOneProbeAcrossReportStages()
    {
        var calls = 0;
        using var scope = NmapObservationScope.Begin();

        Task<IReadOnlyDictionary<int, NmapResult>> Probe()
        {
            calls++;
            return Task.FromResult<IReadOnlyDictionary<int, NmapResult>>(
                new Dictionary<int, NmapResult>());
        }

        await NmapObservationScope.GetAsync("192.168.99.1", [443, 80], Probe, default);
        await NmapObservationScope.GetAsync("192.168.99.1", [80, 443], Probe, default);

        Assert.Equal(1, calls);
    }

    [Fact]
    public void ParseXmlMany_PreservesProductOsCpeAndAllOpenPorts()
    {
        const string xml = """
            <nmaprun><host><ports>
              <port protocol="tcp" portid="135"><state state="open"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows" conf="10"><cpe>cpe:/o:microsoft:windows</cpe></service></port>
              <port protocol="tcp" portid="902"><state state="open"/><service name="vmware-auth" product="VMware Authentication Daemon" version="1.10" extrainfo="Uses VNC" tunnel="ssl" conf="10"/></port>
              <port protocol="tcp" portid="999"><state state="closed"/><service name="unknown" conf="3"/></port>
            </ports></host></nmaprun>
            """;

        var results = NmapEnhancer.ParseXmlMany(xml);

        Assert.Equal(2, results.Count);
        Assert.Equal("Microsoft Windows RPC", results[135].Product);
        Assert.Equal("Windows", results[135].OsType);
        Assert.Contains("cpe:/o:microsoft:windows", results[135].Cpes);
        Assert.Equal("1.10", results[902].Version);
        Assert.Equal("ssl", results[902].Tunnel);
    }

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

    [Fact]
    public async Task ProcessStatusRetainsPidAndExitCode_InsteadOfSilentEmptyResult()
    {
        var psi = SleepProcess();
        psi.ArgumentList.Clear();
        if (OperatingSystem.IsWindows())
        {
            psi.ArgumentList.Add("-NoProfile"); psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add("exit 7");
        }
        else { psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("exit 7"); }
        var result = await NmapEnhancer.RunProcessDetailedAsync(psi, TimeSpan.FromSeconds(10), default);
        Assert.Equal("exit_error", result.Status);
        Assert.Equal(7, result.ExitCode);
        Assert.True(result.ProcessId > 0);
        Assert.Null(result.Xml);
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
