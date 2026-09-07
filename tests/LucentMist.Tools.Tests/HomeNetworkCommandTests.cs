using LucentMist.CLI;
using LucentMist.Scanning.Monitoring;

namespace LucentMist.Tools.Tests;

public class HomeNetworkCommandTests
{
    [Fact]
    public void OneCycleDoesNotPromiseAnotherThirtyMinuteWait()
    {
        Assert.DoesNotContain("等待", HomeNetworkCommands.ScheduleDescription(1, 30));
        Assert.Contains("完成后退出", HomeNetworkCommands.ScheduleDescription(1, 30));
        Assert.Contains("等待 30 分钟", HomeNetworkCommands.ScheduleDescription(null, 30));
    }

    [Fact]
    public void AnalysisCoverageNotesStayVisibleOutsideAlerts()
    {
        var time = DateTimeOffset.UtcNow;
        var device = new KnownDevice(new("192.168.99.1", null, "未知", "router", [80], Warnings: ["NVD timeout"]), time, time, true);
        Assert.Equal("192.168.99.1：NVD timeout", Assert.Single(HomeNetworkCommands.AnalysisStatus([device])));
        Assert.Empty(HomeNetworkCommands.AnalysisStatus([device with { Present = false }]));
    }
    [Fact]
    public void AndroidServiceEvidenceIsVisible_NotInferredAsAModel()
    {
        var device = new MonitorDevice("192.168.99.10", null, "未知", "android-99.local", [], Model: "未知（未收到型号）", MdnsServices: ["_adb._tcp.local"]);
        var output = HomeNetworkCommands.DeviceDescription(device);
        Assert.Contains("mDNS 声明：_adb", output);
        Assert.Contains("非型号确认", output);
        Assert.Contains("未知（未收到型号）", output);
    }
    [Fact]
    public void MonitorArgumentsSupportEqualsAndSeparateValues()
    {
        var args = HomeNetworkCommands.Parse(["--interval=30", "--subnet", "192.168.99.0/24", "--once"], ["--once"], ["--interval", "--subnet"]);
        Assert.Equal("30", args["--interval"]);
        Assert.Equal("192.168.99.0/24", args["--subnet"]);
        Assert.Equal("true", args["--once"]);
    }

    [Theory]
    [InlineData("--interval")]
    [InlineData("--interval=")]
    [InlineData("--interva=1")]
    [InlineData("--once=false")]
    public void InvalidArgumentsAreNotSilentlyIgnored(string arg) =>
        Assert.Throws<ArgumentException>(() => HomeNetworkCommands.Parse([arg], ["--once"], ["--interval"]));

    [Fact]
    public void FailedPortScanRetainedBaselineIsVisiblyHistorical()
    {
        var time = DateTimeOffset.UtcNow;
        var device = new KnownDevice(new("192.168.99.1", null, "ZTE", "router", [80]), time, time, true, PortsObservedAt: time);
        var output = HomeNetworkCommands.PortObservation(device);
        Assert.Contains("本次扫描失败，保留历史", output);
        Assert.Contains("80", output);
        Assert.Contains("观测于", output);
    }

    [Fact]
    public void UnconfirmedIdentityDoesNotDisplayCurrentResponseAsTrusted()
    {
        var time = DateTimeOffset.UtcNow;
        var device = new KnownDevice(new("192.168.99.1", "00:11:22:33:44:55", "ZTE", "router", [80]), time, time, true,
            Trusted: true, PortsObservedAt: time, IdentityConfirmed: false);
        Assert.Contains("信任不适用于当前响应", HomeNetworkCommands.IdentityObservation(device));
        Assert.DoesNotContain("/可信", HomeNetworkCommands.IdentityObservation(device));
        Assert.Contains("身份未确认，保留历史", HomeNetworkCommands.PortObservation(device));
    }

    [Theory]
    [InlineData("possible_same_device", "疑似同一设备")]
    [InlineData("identity_conflict", "身份待核实")]
    public void WeakAssociationIsVisibleWithoutClaimingTrustedIdentity(string status, string evidence)
    {
        var time = DateTimeOffset.UtcNow;
        var item = new KnownDevice(new("192.168.77.3", "06:11:22:33:44:55", "未知", "android-99.local", []), time, time, true,
            Association: new(status, ["mac:02:11:22:33:44:55"], evidence));
        var output = HomeNetworkCommands.IdentityObservation(item);
        Assert.Contains(evidence, output);
        Assert.Contains("不继承信任", output);
        Assert.DoesNotContain("/可信", output);
        Assert.Contains("已显式信任\n当前 MAC", HomeNetworkCommands.IdentityObservation(item with { Trusted = true }));
    }

    [Theory]
    [InlineData("192.168.99.0/24")]
    [InlineData("1.1.1.1")]
    [InlineData("::1")]
    public void InvalidGatewayIsNotSilentlySkippedAsASuccessfulDiagnosis(string gateway) =>
        Assert.Throws<ArgumentException>(() => HomeNetworkCommands.ValidateGateway(gateway));

    [Fact]
    public void SuspectedReplacementIsOneRow_OfflineUnrelatedDeviceStaysSeparate()
    {
        var time = DateTimeOffset.UtcNow;
        var old = new KnownDevice(new("192.168.77.6", "02:11:22:33:44:55", "未知", "android-99.local", [80]), time, time, false);
        var current = new KnownDevice(new("192.168.77.21", "06:11:22:33:44:66", "未知", "android-99.local", []), time, time, true,
            Association: new("possible_same_device", [old.Device.Id], "name"));
        var offline = old with { Device = old.Device with { Ip = "192.168.77.10", Mac = "0A:11:22:33:44:77", Name = "another-device" } };
        var rows = MonitorDevicePresentation.Rows([old, current, offline]);
        Assert.Equal(current.Device.Id, Assert.Single(rows, r => r.Item.Present).Item.Device.Id);
        Assert.Equal(offline.Device.Id, Assert.Single(rows, r => !r.Item.Present).Item.Device.Id);
        Assert.Contains("疑似 = 旧 192.168.77.6", rows.Single(r => r.Item.Present).Label);
    }

    [Fact]
    public void ConfirmedAliasesRemainOneRowWhenOldMacReturns_ButConcurrentResponsesAreNotHidden()
    {
        var time = DateTimeOffset.UtcNow;
        var oldDevice = new MonitorDevice("192.168.77.6", "02:11:22:33:44:55", "未知", "android-99.local", [80]);
        var newDevice = oldDevice with { Ip = "192.168.77.21", Mac = "06:11:22:33:44:66", OpenPorts = [443] };
        var current = new KnownDevice(newDevice, time, time, false, Trusted: true, PortHistory: new() { [443] = new(true, time) },
            Association: new("confirmed_same_device", [oldDevice.Id], "confirmed"));
        var old = new KnownDevice(oldDevice, time, time, true, Trusted: true, PortHistory: new() { [80] = new(true, time) }, MergedIntoId: newDevice.Id);
        var row = Assert.Single(MonitorDevicePresentation.Rows([old, current]));
        Assert.Equal(oldDevice.Mac, row.Item.Device.Mac);
        Assert.Contains("已确认 = 旧", row.Label);
        Assert.Equal(new[] { 80, 443 }, row.Item.Device.OpenPorts);
        Assert.All(MonitorDevicePresentation.Rows([old, current with { Present = true }]), r => Assert.Contains("身份待核实", r.Label));
    }

    [Theory]
    [InlineData("--merge")]
    [InlineData("--merge", "192.168.77.6")]
    [InlineData("--merge", "192.168.77.6", "--devices")]
    public void MergeRequiresBothIdentities(params string[] args) =>
        Assert.Throws<ArgumentException>(() => HomeNetworkCommands.Parse(args, ["--devices"], ["--merge"]));
}
