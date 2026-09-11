using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using LucentMist.Tools;
using LucentMist.Tools.Discovery;

namespace LucentMist.Scanning.Tests;

public sealed class MonitorDhcpTests : IDisposable
{
    private readonly string _directory = Path.Combine(AppContext.BaseDirectory, "dhcp-tests", Guid.NewGuid().ToString("N"));
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.77.0/24", "80");
    private static readonly DateTimeOffset Time = DateTimeOffset.Parse("2026-09-08T00:00:00Z");
    private static readonly MonitorDevice Old = new("192.168.77.6", "02:11:22:33:44:55", "未知", "android-99.local", [80]);
    private static readonly MonitorDevice New = new("192.168.77.21", "06:11:22:33:44:66", "未知", "未知", []);
    private MonitorStore Store => new(Path.Combine(_directory, "monitor.db"));
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    private static DhcpResult Record(string? hostname = "android-99", string? mac = null) => new("0.0.0.0", hostname,
        "android-dhcp-13", [1, 3, 6], Time, mac ?? New.Mac!, "passive-sniff", 1, null, null, null, null, null, "");
    private static DhcpCaptureResult Capture(params DhcpResult[] records) => new("passive-observations", "记录来自 DHCP 报文", records);

    [Fact]
    public void DhcpMatchesObservedMac_NotServerIp_AndNeverInventsVendor()
    {
        var current = NetworkMonitorScanner.WithDhcp(New, Capture(Record()));
        Assert.Equal("android-99", current.Name);
        Assert.Equal("android-99", current.DhcpHostname);
        Assert.Equal("未知", current.Vendor);
        Assert.Equal("android-dhcp-13", current.DhcpVendorClass);
        Assert.Equal(Time, current.DhcpObserved);
        Assert.Null(NetworkMonitorScanner.WithDhcp(New with { Mac = null }, Capture(Record())).DhcpHostname);
        Assert.Null(NetworkMonitorScanner.WithDhcp(Old, Capture(Record())).DhcpHostname);
    }

    [Fact]
    public void StoredDhcpHostnameCorroboratesRotation_OnlyExplicitMergeTransfersTrust()
    {
        Store.Apply(Scope, new(true, [Old]), Time);
        Store.Trust(Scope, Old.Ip);
        var current = NetworkMonitorScanner.WithDhcp(New, Capture(Record()));
        Store.Apply(Scope, new(true, [current]), Time.AddMinutes(1));
        var saved = Store.ListDevices(Scope).Single(d => d.Device.Id == current.Id);
        Assert.Equal("possible_same_device", saved.Association!.Status);
        Assert.False(saved.Trusted);
        Assert.Equal("android-99", saved.Device.DhcpHostname);
        Assert.Equal("passive-sniff", saved.Device.DhcpSourceMode);
        Assert.Contains(Store.ListAlerts(Scope), a => a.Message.Contains("monitor --merge") && a.Message.Contains(Old.Ip));
        var merged = Store.Merge(Scope, Old.Ip, New.Ip, Time.AddMinutes(2));
        Assert.True(merged.Trusted);
        Assert.Equal(Time, merged.FirstSeen);
        Assert.Equal("android-99", merged.Device.DhcpHostname);
    }

    [Fact]
    public void ConflictingMdnsAndDhcpNamesRequireReview_NotTrustOrAutomaticMerge()
    {
        Store.Apply(Scope, new(true, [Old]), Time);
        var device = New with { Name = "another-phone.local", DhcpHostname = "android-99", DhcpObserved = Time };
        var current = Store.Apply(Scope, new(true, [device]), Time.AddMinutes(1)).Devices.Single(d => d.Device.Id == device.Id);
        Assert.Equal("identity_conflict", current.Association!.Status);
        Assert.False(current.Trusted);
    }

    [Fact]
    public void MultipleDhcpNamesForOneMacDoNotPickAnArbitraryIdentity()
    {
        var device = NetworkMonitorScanner.WithDhcp(New, Capture(Record(), Record("different-device")));
        Assert.Equal("未知", device.Name);
        Assert.Null(device.DhcpHostname);
        var saved = Assert.Single(Store.Apply(Scope, new(true, [device]), Time).Devices);
        Assert.Equal("identity_conflict", saved.Association!.Status);
    }

    [Fact]
    public void FailedDhcpIsVisibleWithoutFakingDiscoveryFailureOrErasingPorts()
    {
        var current = NetworkMonitorScanner.WithDhcp(New, new("permission-required", "权限不足，未采集", []));
        Assert.Contains(current.Warnings!, w => w.Contains("permission-required"));
        Assert.Empty(current.OpenPorts!);
        Assert.Null(current.DhcpHostname);
    }

    [Fact]
    public void OldJsonNeedsNoDatabaseMigration_AndMissingDhcpPreservesHistoricalEvidence()
    {
        var old = JsonSerializer.Deserialize<MonitorDevice>("""{"Ip":"192.168.77.21","Mac":"06:11:22:33:44:66","Name":"未知","Vendor":"未知","OpenPorts":[]}""")!;
        Assert.Null(old.DhcpHostname);
        Assert.Null(old.DhcpObserved);
        Store.Apply(Scope, new(true, [NetworkMonitorScanner.WithDhcp(old, Capture(Record()))]), Time);
        var later = Assert.Single(Store.Apply(Scope, new(true, [old]), Time.AddMinutes(1)).Devices);
        Assert.Equal("android-99", later.Device.DhcpHostname);
        Assert.Equal(Time, later.Device.DhcpObserved);
    }

    [Fact]
    public async Task ScannerCallsDhcpOncePerSubnet_NotOncePerUnknownDevice()
    {
        var calls = 0;
        var discovery = new Fake(new
        {
            deviceDetails = new[] {
            new { ip = Old.Ip, mac = Old.Mac, vendor = "未知", name = "未知" },
            new { ip = New.Ip, mac = New.Mac, vendor = "未知", name = "未知" } }
        });
        var empty = new Fake(new { openPorts = Array.Empty<int>() });
        var scanner = new NetworkMonitorScanner(discovery, empty, empty, empty, (subnet, _) =>
        {
            Assert.Equal(Scope.Subnet, subnet);
            calls++;
            return Task.FromResult(Capture(Record()));
        });
        var result = await scanner.CaptureAsync(Scope, false, default);
        Assert.True(result.DiscoverySucceeded);
        Assert.Equal(1, calls);
        Assert.Equal("android-99", result.Devices.Single(d => d.Id == New.Id).DhcpHostname);
    }

    private sealed class Fake(object data) : ITool
    {
        public string Name => "fake";
        public string Description => "test fixture";
        public ToolParameter[] Parameters => [];
        public Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default) =>
            Task.FromResult(ToolResult.Ok(JsonSerializer.Serialize(data), TimeSpan.Zero));
    }
}
