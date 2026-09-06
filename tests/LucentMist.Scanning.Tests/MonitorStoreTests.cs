using LucentMist.Scanning.Monitoring;

namespace LucentMist.Scanning.Tests;

public sealed class MonitorStoreTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"lmist-monitor-{Guid.NewGuid():N}.db");
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.99.0/24", "22,80,443");
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-06T00:00:00Z");
    private MonitorStore Store => new(_path);
    private static MonitorDevice A(int[]? ports = null) => new("192.168.99.1", "00:11:22:33:44:55", "ZTE", "router", ports ?? [80]);
    private static MonitorDevice B => new("192.168.99.6", "00:11:22:33:44:66", "未知", "android-99.local", [443]);
    public void Dispose() { foreach (var suffix in new[] { "", "-wal", "-shm" }) if (File.Exists(_path + suffix)) File.Delete(_path + suffix); }

    [Fact]
    public void FirstScanCreatesBaseline_SecondUnchangedHasNoAlerts_AfterReopen()
    {
        var first = Store.Apply(Scope, new(true, [A(), B]), Now);
        Assert.True(first.BaselineCreated);
        Assert.Empty(first.Alerts);
        var next = Store.Apply(Scope, new(true, [A(), B]), Now.AddMinutes(30));
        Assert.False(next.BaselineCreated);
        Assert.Empty(next.Alerts);
        Assert.All(next.Devices, d => Assert.Equal(Now, d.FirstSeen));
        Assert.All(next.Devices, d => Assert.Equal(Now.AddMinutes(30), d.LastSeen));
    }
    [Fact]
    public void MissingMacDoesNotCreateFalseStrangerAndDisappearanceOrHideOtherNewDevices()
    {
        Store.Apply(Scope, new(true, [A()]), Now);
        Store.Trust(Scope, A().Ip);
        var update = Store.Apply(Scope, new(true, [A() with { Mac = null }, B]), Now.AddMinutes(1));
        Assert.DoesNotContain(update.Alerts, a => a.Ip == A().Ip && a.Kind is "new_device" or "missing_device");
        Assert.Contains(update.Alerts, a => a.Ip == A().Ip && a.Kind == "identity_unconfirmed");
        Assert.Contains(update.Alerts, a => a.Ip == B.Ip && a.Kind == "new_device" && a.Priority == "high");
        var known = update.Devices.Single(d => d.Device.Ip == A().Ip);
        Assert.Equal(Now, known.LastSeen);
        Assert.False(known.IdentityConfirmed);
        Assert.Throws<ArgumentException>(() => Store.Trust(Scope, A().Ip));
        Assert.Contains("partial", update.Summary);
        var retry = Store.Apply(Scope, new(true, [A() with { Mac = null }, B]), Now.AddMinutes(2));
        Assert.DoesNotContain(retry.Alerts, a => a.Kind == "identity_unconfirmed");
        var recovered = Store.Apply(Scope, new(true, [A(), B]), Now.AddMinutes(3));
        Assert.DoesNotContain(recovered.Alerts, a => a.Kind == "new_device");
        Assert.All(recovered.Devices, d => Assert.True(d.IdentityConfirmed));
        Assert.Equal(Now.AddMinutes(3), recovered.Devices.Single(d => d.Device.Ip == A().Ip).LastSeen);
    }
    [Fact]
    public void NewDeviceIsHigh_MissingIsLow_EventsDoNotRepeatEveryPoll()
    {
        Store.Apply(Scope, new(true, [A()]), Now);
        var update = Store.Apply(Scope, new(true, [B]), Now.AddMinutes(1));
        Assert.Contains(update.Alerts, a => a.Kind == "new_device" && a.Priority == "high");
        Assert.Contains(update.Alerts, a => a.Kind == "missing_device" && a.Priority == "low");
        Assert.Empty(Store.Apply(Scope, new(true, [B]), Now.AddMinutes(2)).Alerts);
        Assert.Equal(2, Store.ListAlerts(Scope).Length);
    }
    [Fact]
    public void PortAddedIsMedium_RemovalIsOnlyNotObserved()
    {
        Store.Apply(Scope, new(true, [A([22, 80])]), Now);
        var update = Store.Apply(Scope, new(true, [A([80, 443])]), Now.AddMinutes(1));
        Assert.Contains(update.Alerts, a => a.Kind == "port_added" && a.Priority == "medium" && a.Message.Contains("443"));
        Assert.Contains(update.Alerts, a => a.Kind == "port_not_observed" && a.Priority == "low" && a.Message.Contains("不能确定已关闭"));
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedOrEmptyDiscoveryCannotEraseBaselineOrReportMassDisappearance(bool success)
    {
        Store.Apply(Scope, new(true, [A(), B]), Now);
        var update = Store.Apply(Scope, new(success, [], "probe failed"), Now.AddMinutes(1));
        Assert.False(update.Applied);
        Assert.All(update.Devices, d => Assert.True(d.Present));
        Assert.DoesNotContain(update.Alerts, a => a.Kind == "missing_device");
        Assert.Equal(Now, update.Devices[0].LastSeen);
    }
    [Fact]
    public void PortFailurePreservesPreviousPortsAndLaterChangeRemainsDetectable()
    {
        Store.Apply(Scope, new(true, [A([80])]), Now);
        var failed = Store.Apply(Scope, new(true, [A() with { OpenPorts = null }]), Now.AddMinutes(1));
        Assert.Equal(new[] { 80 }, Assert.Single(failed.Devices).Device.OpenPorts);
        Assert.Equal(Now, failed.Devices[0].PortsObservedAt);
        Assert.False(failed.Devices[0].LastPortScanSucceeded);
        Assert.DoesNotContain(failed.Alerts, a => a.Kind == "port_not_observed");
        Assert.Contains(Store.Apply(Scope, new(true, [A([80, 443])]), Now.AddMinutes(2)).Alerts, a => a.Kind == "port_added");
    }
    [Fact]
    public void TrustedMacSuppressesStrangerAlert_WithoutTransferringTrustToReusedIp()
    {
        Store.Apply(Scope, new(true, [A()]), Now);
        Store.Trust(Scope, B.Mac!);
        Assert.DoesNotContain(Store.Apply(Scope, new(true, [A(), B]), Now.AddMinutes(1)).Alerts, a => a.Kind == "new_device");
        Assert.Equal(A().Mac, Store.Trust(Scope, A().Ip));
        var intruder = B with { Ip = A().Ip, Mac = "02:AA:BB:CC:DD:EE" };
        var collision = Store.Apply(Scope, new(true, [intruder, B]), Now.AddMinutes(2));
        Assert.Contains(collision.Alerts, a => a.Ip == intruder.Ip && a.Kind == "identity_association" && a.Priority == "medium");
        Assert.False(collision.Devices.Single(d => d.Device.Id == intruder.Id).Trusted);
    }
    [Fact]
    public void IpWithoutMacCannotBePermanentlyTrusted()
    {
        Store.Apply(Scope, new(true, [A() with { Mac = null }]), Now);
        Assert.Throws<ArgumentException>(() => Store.Trust(Scope, A().Ip));
    }
    [Fact]
    public void StableMacChangingIpIsNotANewDevice()
    {
        Store.Apply(Scope, new(true, [A()]), Now);
        var update = Store.Apply(Scope, new(true, [A() with { Ip = "192.168.99.20", Mac = "001122334455" }]), Now.AddMinutes(1));
        Assert.Single(update.Devices);
        Assert.Contains(update.Alerts, a => a.Kind == "ip_changed");
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "missing_device");
    }
    [Fact]
    public void DifferentPortScopeSharesBaseline_WithoutFalsePortClosure()
    {
        Store.Apply(Scope, new(true, [A([80, 443])]), Now);
        var other = MonitorScope.Create(Scope.Subnet, "80");
        var update = Store.Apply(other, new(true, [A([80])]), Now.AddMinutes(1));
        Assert.False(update.BaselineCreated);
        Assert.Empty(update.Alerts);
        Assert.Equal(new[] { 80, 443 }, Assert.Single(update.Devices).Device.OpenPorts);
        Assert.Equal(Now, update.Devices[0].PortHistory![443].At);
        Assert.Equal(Now.AddMinutes(1), update.Devices[0].PortHistory![80].At);
        Assert.Single(Store.ListDevices(MonitorScope.Create(Scope.Subnet, "22")));
    }
    [Fact]
    public void ServiceAndVendorChangesHaveEvidence_UnknownProbeDoesNotEraseIt()
    {
        Store.Apply(Scope, new(true, [A() with { Services = new() { [80] = "nginx/1.24.0" } }]), Now);
        Store.Apply(Scope, new(true, [A() with { Vendor = "未知", Services = [] }]), Now.AddMinutes(1));
        var update = Store.Apply(Scope, new(true, [A() with { Vendor = "Other", Services = new() { [80] = "Apache/2.4.60" } }]), Now.AddMinutes(2));
        Assert.Contains(update.Alerts, a => a.Kind == "vendor_changed");
        Assert.Contains(update.Alerts, a => a.Kind == "service_changed");
    }
    [Fact]
    public void VulnerabilityCandidatesAreNotAutomaticallyMarkedResolvedAfterFailure()
    {
        Store.Apply(Scope, new(true, [A() with { Vulnerabilities = ["22:CVE-2024-6387"] }]), Now);
        Store.Apply(Scope, new(true, [A() with { Vulnerabilities = null, Warnings = ["failed"] }]), Now.AddMinutes(1));
        var update = Store.Apply(Scope, new(true, [A() with { Vulnerabilities = ["22:CVE-2024-6387"] }]), Now.AddMinutes(2));
        Assert.DoesNotContain(update.Alerts, a => a.Kind == "vulnerability_candidate");
    }
    [Fact]
    public void AnalysisCoverageIsPersistedStatus_NotAnAlert_AndDoesNotHideNewDevices()
    {
        var warned = A() with { Warnings = ["NVD timeout：覆盖不完整"] };
        for (var i = 0; i < 3; i++)
        {
            var update = Store.Apply(Scope, new(true, [warned]), Now.AddMinutes(i));
            Assert.Empty(update.Alerts);
            Assert.Contains("partial", update.Summary);
        }
        Assert.Empty(Store.ListAlerts(Scope));
        Assert.Contains("NVD timeout：覆盖不完整", Assert.Single(Store.ListDevices(Scope)).Device.Warnings!);
        var changed = Store.Apply(Scope, new(true, [warned, B]), Now.AddMinutes(4));
        Assert.Equal("new_device", Assert.Single(changed.Alerts).Kind);
        Assert.Equal("high", Assert.Single(Store.ListAlerts(Scope)).Priority);
    }
    [Theory]
    [InlineData("1.1.1.0/24", "80")]
    [InlineData("192.168.0.0/16", "80")]
    [InlineData("192.168.99.0/24", "1-65535")]
    [InlineData("192.168.99.0/24", "0")]
    public void InvalidOrExcessiveScopesAreRejected(string subnet, string ports) => Assert.Throws<ArgumentException>(() => MonitorScope.Create(subnet, ports));
    [Fact]
    public void ScopeCanonicalizationDoesNotDependOnHostBitsOrPortOrdering() =>
        Assert.Equal(Scope, MonitorScope.Create("192.168.99.9/24", "443,22,80,22"));

    [Fact]
    public void DuplicateMacCannotSilentlyHideOneDeviceOrReplaceTheBaseline()
    {
        Store.Apply(Scope, new(true, [A(), B]), Now);
        var update = Store.Apply(Scope, new(true, [A(), A() with { Ip = B.Ip }]), Now.AddMinutes(1));
        Assert.False(update.Applied);
        Assert.Contains(update.Alerts, a => a.Kind == "monitor_unavailable" && a.Message.Contains("身份存在歧义"));
        Assert.All(update.Devices, d => Assert.Equal(Now, d.LastSeen));
    }
}
