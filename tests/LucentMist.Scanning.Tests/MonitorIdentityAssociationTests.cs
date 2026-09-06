using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Tests;

public sealed class MonitorIdentityAssociationTests : IDisposable
{
    private readonly string _directory = Path.Combine(AppContext.BaseDirectory, "identity-tests", Guid.NewGuid().ToString("N"));
    private string Db => Path.Combine(_directory, "monitor.db");
    private MonitorStore Store => new(Db);
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.77.0/24", "80,443");
    private static readonly DateTimeOffset Time = DateTimeOffset.Parse("2026-09-07T00:00:00Z");
    private static readonly MonitorDevice Original = new("192.168.77.2", "02:11:22:33:44:55", "随机 MAC", "android-99.local", [80], Model: "Test-Phone", MdnsServices: ["_adb._tcp.local"]);
    private static MonitorDevice Rotated => Original with { Ip = "192.168.77.3", Mac = "06:11:22:33:44:66", Name = "android-99.local.", OpenPorts = [443] };
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    [Fact]
    public void UniqueHostnameAfterRotation_LinksButNeverTransfersTrustOrPortBaseline()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        var update = Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(1));
        var current = update.Devices.Single(d => d.Device.Id == Rotated.Id);
        var history = update.Devices.Single(d => d.Device.Id == Original.Id);
        Assert.Equal("possible_same_device", current.Association!.Status);
        Assert.Equal(new[] { Original.Id }, current.Association.RelatedDeviceIds);
        Assert.False(current.Trusted);
        Assert.True(history.Trusted);
        Assert.False(history.Present);
        Assert.False(history.IdentityConfirmed);
        Assert.Equal(Time, history.LastSeen);
        Assert.Equal(Time, history.PortsObservedAt);
        Assert.Equal(new[] { 80 }, history.Device.OpenPorts);
        Assert.Equal(new[] { 443 }, current.Device.OpenPorts);
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "missing_device" or "port_added" or "port_not_observed");
        Assert.Equal("identity_association", Assert.Single(update.Alerts).Kind);
        Assert.Contains("疑似同一设备", update.Alerts[0].Message);
        Assert.Empty(Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(2)).Alerts);
        Store.Trust(Scope, Rotated.Ip);
        Assert.True(Store.ListDevices(Scope).Single(d => d.Device.Id == Rotated.Id).Trusted);
    }

    [Fact]
    public void RepeatedRotationsKeepOneTentativeRoot_WithoutMergingMacRows()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(1));
        var third = Rotated with { Ip = "192.168.77.4", Mac = "0A:11:22:33:44:77" };
        var update = Store.Apply(Scope, new(true, [third]), Time.AddMinutes(2));
        var current = update.Devices.Single(d => d.Device.Id == third.Id);
        Assert.Equal("possible_same_device", current.Association!.Status);
        Assert.Equal(new[] { Original.Id }, current.Association.RelatedDeviceIds);
        Assert.Equal(3, update.Devices.Length);
        Assert.False(current.Trusted);
        Assert.Single(update.Devices, d => d.Present);
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "missing_device");
    }

    [Fact]
    public void SimultaneouslyObservedNamesAreConflict_NotSameDeviceOrTrusted()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        var update = Store.Apply(Scope, new(true, [Original, Rotated]), Time.AddMinutes(1));
        var other = update.Devices.Single(d => d.Device.Id == Rotated.Id);
        Assert.Equal("identity_conflict", other.Association!.Status);
        Assert.False(other.Trusted);
        Assert.Contains(update.Alerts, a => a.Priority == "medium" && a.Message.Contains("身份待核实"));
        Assert.DoesNotContain(update.Alerts, a => a.Kind == "new_device");
    }

    [Fact]
    public void MultipleHistoricalMatchesAreConflict_NotFirstEnumerationWins()
    {
        var duplicate = Original with { Ip = "192.168.77.8", Mac = "0E:11:22:33:44:88" };
        Store.Apply(Scope, new(true, [Original, duplicate]), Time);
        var update = Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(1));
        var current = update.Devices.Single(d => d.Device.Id == Rotated.Id);
        Assert.Equal("identity_conflict", current.Association!.Status);
        Assert.Equal(2, current.Association.RelatedDeviceIds.Length);
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "missing_device");
    }

    [Fact]
    public void MatchingNameWithConflictingModelRequiresReview()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        var changed = Rotated with { Model = "Different-Phone" };
        var update = Store.Apply(Scope, new(true, [changed]), Time.AddMinutes(1));
        Assert.Equal("identity_conflict", update.Devices.Single(d => d.Device.Id == changed.Id).Association!.Status);
    }

    [Theory]
    [InlineData("未知（未获得有效名称响应）")]
    [InlineData("网页：Android Router")]
    [InlineData("_adb._tcp.local")]
    [InlineData("")]
    public void MissingHostnameOrGenericServiceDoesNotInventAssociationOrStranger(string name)
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        var changed = Rotated with { Name = name };
        var update = Store.Apply(Scope, new(true, [changed]), Time.AddMinutes(1));
        var current = update.Devices.Single(d => d.Device.Id == changed.Id);
        Assert.Equal("identity_unconfirmed", current.Association!.Status);
        Assert.Empty(current.Association.RelatedDeviceIds);
        Assert.False(current.Trusted);
        Assert.DoesNotContain(update.Alerts, a => a.Kind == "new_device");
        Assert.Contains("无响应不等于未广播", current.Association.Evidence);
    }

    [Fact]
    public void ScopeIsolation_AndOldSerializedBaselineStillDeserialize()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        var otherScope = MonitorScope.Create("192.168.88.0/24", "80");
        var other = Rotated with { Ip = "192.168.88.3" };
        var update = Store.Apply(otherScope, new(true, [other]), Time);
        Assert.False(Assert.Single(update.Devices).Trusted);
        Assert.Empty(update.Devices[0].Association!.RelatedDeviceIds);
        const string oldJson = """
            {"Device":{"Ip":"192.168.77.2","Mac":"02:11:22:33:44:55","Vendor":"unknown","Name":"android-99.local","OpenPorts":[80]},
             "FirstSeen":"2026-09-07T00:00:00Z","LastSeen":"2026-09-07T00:00:00Z","Present":true}
            """;
        Assert.Null(JsonSerializer.Deserialize<KnownDevice>(oldJson)!.Association);
    }

    [Fact]
    public void StoredBaselineWithoutAssociationFieldStillCorrelates_AndKeepsOriginalTrust()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Db, Pooling = false }.ToString()))
        {
            db.Open();
            using var command = db.CreateCommand();
            command.CommandText = "UPDATE monitor_devices SET state_json=json_remove(state_json,'$.Association')";
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        Assert.Null(Assert.Single(Store.ListDevices(Scope)).Association);
        var update = Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(1));
        var historical = update.Devices.Single(d => d.Device.Id == Original.Id);
        var current = update.Devices.Single(d => d.Device.Id == Rotated.Id);
        Assert.True(historical.Trusted);
        Assert.Equal(Time, historical.FirstSeen);
        Assert.Equal(Time, historical.LastSeen);
        Assert.Equal("possible_same_device", current.Association!.Status);
        Assert.False(current.Trusted);
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "missing_device");
    }

    [Fact]
    public void AssociationCannotTurnFailedPortScanIntoHistoricalOpenPortsFromAnotherMac()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        var failed = Rotated with { OpenPorts = null };
        var update = Store.Apply(Scope, new(true, [failed]), Time.AddMinutes(1));
        var current = update.Devices.Single(d => d.Device.Id == failed.Id);
        Assert.Equal("possible_same_device", current.Association!.Status);
        Assert.Null(current.Device.OpenPorts);
        Assert.Null(current.PortsObservedAt);
        Assert.False(current.LastPortScanSucceeded);
    }

    [Fact]
    public void NameResponseRecoveryAssociatesPreviouslyUnconfirmedMac_WithoutTrustTransfer()
    {
        Store.Apply(Scope, new(true, [Original]), Time);
        Store.Trust(Scope, Original.Ip);
        Store.Apply(Scope, new(true, [Rotated with { Name = "未知" }]), Time.AddMinutes(1));
        var recovered = Store.Apply(Scope, new(true, [Rotated]), Time.AddMinutes(2));
        var current = recovered.Devices.Single(d => d.Device.Id == Rotated.Id);
        Assert.Equal("possible_same_device", current.Association!.Status);
        Assert.False(current.Trusted);
        Assert.DoesNotContain(recovered.Alerts, a => a.Kind == "new_device");
    }

    [Fact]
    public void CyclicStoredLinksDoNotHangOrCollapseTwoIdentities()
    {
        var first = new KnownDevice(Original, Time, Time, true, Association: new("possible_same_device", [Rotated.Id], "test"));
        var second = new KnownDevice(Rotated, Time, Time, true, Association: new("possible_same_device", [Original.Id], "test"));
        var old = new Dictionary<string, KnownDevice> { [Original.Id] = first, [Rotated.Id] = second };
        Assert.Equal(Original.Id, MonitorIdentityMatcher.Root(Original.Id, old));
        Assert.Equal(Rotated.Id, MonitorIdentityMatcher.Root(Rotated.Id, old));
        var third = Rotated with { Mac = "0A:11:22:33:44:77" };
        Assert.Equal("identity_conflict", MonitorIdentityMatcher.Match(third, old, [third])!.Status);
    }
}
