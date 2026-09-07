using System.Diagnostics;
using System.Text;
using System.Text.Json;
using LucentMist.Scanning.Monitoring;

namespace LucentMist.Tools.Tests;

public sealed class MonitorCliIntegrationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "lmist-cli-sequence-" + Guid.NewGuid().ToString("N"));
    private const string Subnet = "192.168.77.0/24";
    private static readonly MonitorDevice Router = new("192.168.77.1", "00:11:22:33:44:55", "fixture-vendor", "fixture-router", [80]);
    private static readonly MonitorDevice Phone = new("192.168.77.2", "00:11:22:33:44:66", "未知", "fixture-phone", [80]);

    public MonitorCliIntegrationTests() => Directory.CreateDirectory(_directory);
    public void Dispose() => Directory.Delete(_directory, true);

    private Task Snapshot(params MonitorDevice[] devices) => File.WriteAllTextAsync(Path.Combine(_directory, "snapshot.json"), JsonSerializer.Serialize(new NetworkSnapshot(true, devices)));

    [Fact]
    public async Task RealCommandSequence_CustomPorts_QueryWithoutPorts_Trust_NewDeviceAlert()
    {
        await Snapshot(Router);
        var first = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        Assert.Contains("首轮基线", first);
        Assert.DoesNotContain("等待 30 分钟", first);
        var devices = await Run("monitor", "--devices", "--subnet", Subnet);
        Assert.Contains(Router.Ip, devices);
        Assert.Contains("暂无已记录告警", await Run("monitor", "--alerts", "--subnet", Subnet));

        // No subnet/ports here: exercise the same default-subnet path as a user.
        Assert.Contains("已信任 MAC", await Run("monitor", "--trust", Router.Ip));
        Assert.Matches(@"192\.168\.77\.1[^\r\n]*观测到/可信", await Run("monitor", "--devices", "--subnet", Subnet));
        await Snapshot(Router, Phone);
        await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        var alerts = await Run("monitor", "--alerts", "--subnet", Subnet);
        Assert.Contains("new_device", alerts);
        Assert.Contains("high", alerts);
        Assert.Contains(Phone.Ip, alerts);
        Assert.DoesNotContain(Router.Ip + " new_device", alerts);
        await Run("monitor", "--trust", Phone.Ip);
        Assert.Matches(@"192\.168\.77\.2[^\r\n]*观测到/可信", await Run("monitor", "--devices"));

        // Reading with defaults or scanning a different range cannot erase the baseline.
        await Snapshot(Router with { OpenPorts = [] }, Phone with { OpenPorts = [] });
        var changedRange = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "443");
        Assert.DoesNotContain("port_not_observed", changedRange);
        Assert.DoesNotContain("new_device", changedRange);
        Assert.Contains("80", await Run("monitor", "--devices"));
    }

    [Fact]
    public async Task RepeatedIncompleteAnalysisShowsStatus_NotAlerts_AndNewDeviceRemainsVisible()
    {
        await Snapshot(Router with { Warnings = ["NVD timeout"] });
        var first = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80", "--check-vulns");
        Assert.Contains("检查状态", first);
        Assert.Contains("NVD timeout", first);
        await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80", "--check-vulns");
        var before = await Run("monitor", "--alerts", "--subnet", Subnet);
        Assert.DoesNotContain("analysis_incomplete", before);
        Assert.Contains("暂无已记录告警", before);
        Assert.Contains("检查状态", await Run("monitor", "--devices"));
        await Snapshot(Router with { Warnings = ["NVD timeout"] }, Phone);
        await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80", "--check-vulns");
        var after = await Run("monitor", "--alerts", "--subnet", Subnet);
        Assert.Contains("new_device", after);
        Assert.DoesNotContain("analysis_incomplete", after);
    }

    [Fact]
    public async Task RandomMacRotation_AssociatesHostname_WithoutStrangerAlertOrTrustInheritance()
    {
        var original = Phone with { Mac = "02:11:22:33:44:66", Name = "android-99.local", MdnsServices = ["_adb._tcp.local"] };
        await Snapshot(Router, original);
        await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        await Run("monitor", "--trust", original.Ip);
        var rotated = original with { Ip = "192.168.77.3", Mac = "06:11:22:33:44:77", Name = "android-99.local." };
        await Snapshot(Router, rotated);
        var update = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        Assert.DoesNotContain("new_device", update);
        Assert.DoesNotContain("missing_device", update);
        Assert.Contains("疑似同一设备", update);
        var devices = await Run("monitor", "--devices", "--subnet", Subnet);
        Assert.Contains(rotated.Ip, devices);
        Assert.Contains("不继承信任", devices);
        Assert.DoesNotMatch(@"192\.168\.77\.3[^\r\n]*观测到/可信", devices);
        var repeat = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        Assert.DoesNotContain("identity_association：", repeat);
        await Run("monitor", "--trust", rotated.Ip);
        Assert.Contains("已显式信任", await Run("monitor", "--devices"));
    }

    [Fact]
    public async Task ConcurrentRandomMacNames_AreVisibleAsConflict_NotAutoTrusted()
    {
        var original = Phone with { Mac = "02:11:22:33:44:66", Name = "android-99.local" };
        await Snapshot(Router, original);
        await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        await Run("monitor", "--trust", original.Ip);
        var other = original with { Ip = "192.168.77.3", Mac = "06:11:22:33:44:77" };
        await Snapshot(Router, original, other);
        var update = await Run("monitor", "--once", "--subnet", Subnet, "--ports", "80");
        Assert.Contains("身份待核实", update);
        Assert.DoesNotContain("new_device", update);
        var devices = await Run("monitor", "--devices");
        Assert.Contains("身份待核实", devices);
        Assert.Contains("不继承信任", devices);
        Assert.DoesNotMatch(@"192\.168\.77\.3[^\r\n]*观测到/可信", devices);
        Assert.Contains("identity_association", await Run("monitor", "--alerts"));
    }

    private async Task<string> Run(params string[] args)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !File.Exists(Path.Combine(root.FullName, "LucentMist.slnx"))) root = root.Parent;
        Assert.NotNull(root);
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        var host = Path.Combine(root.FullName, "tests", "LucentMist.CLI.TestHost", "bin", configuration, "net10.0", "LucentMist.CLI.TestHost.dll");
        Assert.True(File.Exists(host), host);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add(host);
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.Environment["LMIST_DB"] = Path.Combine(_directory, "monitor.db");
        start.Environment["LMIST_TEST_SNAPSHOT"] = Path.Combine(_directory, "snapshot.json");
        start.Environment["LMIST_TEST_SUBNET"] = Subnet;
        start.Environment["NO_COLOR"] = "1";
        start.Environment["COLUMNS"] = "160";
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); throw; }
        var output = await stdout + await stderr;
        Assert.True(process.ExitCode == 0, $"{string.Join(' ', args)}: exit {process.ExitCode}\n{output}");
        return output;
    }
}
