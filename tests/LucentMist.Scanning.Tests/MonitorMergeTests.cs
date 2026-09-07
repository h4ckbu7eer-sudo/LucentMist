using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Tests;

public sealed class MonitorMergeTests : IDisposable
{
    private readonly string _directory = Path.Combine(AppContext.BaseDirectory, "monitor-merge-tests", Guid.NewGuid().ToString("N"));
    private string Db => Path.Combine(_directory, "monitor.db");
    private MonitorStore Store => new(Db);
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.77.0/24", "80,443");
    private static readonly DateTimeOffset Time = DateTimeOffset.Parse("2026-09-07T00:00:00Z");
    private static readonly MonitorDevice Before = new("192.168.77.6", "02:11:22:33:44:55", "未知", "android-99.local", [80]);
    private static readonly MonitorDevice After = Before with { Ip = "192.168.77.21", Mac = "06:11:22:33:44:66", OpenPorts = [443] };
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }
    private void Seed(bool trust = true)
    {
        Store.Apply(Scope with { Ports = "80" }, new(true, [Before]), Time);
        if (trust) Store.Trust(Scope, Before.Ip);
        Store.Apply(Scope with { Ports = "443" }, new(true, [After]), Time.AddMinutes(1));
    }

    [Fact]
    public void ExplicitMergeTransfersTrustFirstSeenAndScopedPortHistory_PersistsAndIsIdempotent()
    {
        Seed();
        Assert.False(Store.ListDevices(Scope).Single(d => d.Device.Id == After.Id).Trusted);
        var merged = Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(2));
        Assert.True(merged.Trusted);
        Assert.Equal(Time, merged.FirstSeen);
        Assert.Equal(Time.AddMinutes(1), merged.LastSeen);
        Assert.Equal(new[] { 80, 443 }, merged.Device.OpenPorts);
        Assert.Equal(Time, merged.PortHistory![80].At);
        Assert.Equal("confirmed_same_device", merged.Association!.Status);
        var archived = Store.ListDevices(Scope).Single(d => d.Device.Id == Before.Id);
        Assert.Equal(After.Id, archived.MergedIntoId);
        Assert.Equal(Time, archived.LastSeen);
        Assert.False(archived.Present);
        Assert.Equal(JsonSerializer.Serialize(merged), JsonSerializer.Serialize(Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(3))));
        Assert.Single(Store.ListAlerts(Scope), a => a.Kind == "identity_merged");
        var update = Store.Apply(Scope with { Ports = "443" }, new(true, [After]), Time.AddMinutes(4));
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "identity_association");
        Assert.EndsWith("；completed", update.Summary);
        Assert.Equal(new[] { 80, 443 }, update.Devices.Single(d => d.Device.Id == After.Id).Device.OpenPorts);
    }

    [Fact]
    public void TwoUntrustedDevicesRemainUntrustedAfterConfirmation()
    {
        Seed(false);
        Assert.False(Store.Merge(Scope, Before.Mac!, After.Mac!, Time.AddMinutes(2)).Trusted);
        Assert.All(Store.ListDevices(Scope), d => Assert.False(d.Trusted));
    }

    [Fact]
    public void NewerClosedPortEvidenceWins_AndFailedScanIsNotMarkedSuccessful()
    {
        Seed();
        Store.Apply(Scope, new(true, [After]), Time.AddMinutes(2));
        Store.Apply(Scope, new(true, [After with { OpenPorts = null }]), Time.AddMinutes(3));
        var merged = Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(4));
        Assert.Equal(new[] { 443 }, merged.Device.OpenPorts);
        Assert.False(merged.PortHistory![80].Open);
        Assert.False(merged.LastPortScanSucceeded);
        Assert.Equal(Time.AddMinutes(2), merged.PortsObservedAt);
    }

    [Fact]
    public void SecondConfirmationKeepsAllArchivedMacsAndEarliestHistory()
    {
        Seed();
        Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(2));
        var third = After with { Ip = "192.168.77.22", Mac = "0A:11:22:33:44:77" };
        var update = Store.Apply(Scope, new(true, [third]), Time.AddMinutes(3));
        Assert.Equal("possible_same_device", update.Devices.Single(d => d.Device.Id == third.Id).Association!.Status);
        Assert.False(update.Devices.Single(d => d.Device.Id == third.Id).Trusted);
        var merged = Store.Merge(Scope, After.Ip, third.Ip, Time.AddMinutes(4));
        Assert.Equal(Time, merged.FirstSeen);
        Assert.True(merged.Trusted);
        Assert.All(Store.ListDevices(Scope).Where(d => d.Device.Id != third.Id), d => Assert.Equal(third.Id, d.MergedIntoId));
    }

    [Fact]
    public void AmbiguousReusedIpRequiresMac_NotFirstMatch()
    {
        Store.Apply(Scope, new(true, [Before]), Time);
        var reused = After with { Ip = Before.Ip };
        Store.Apply(Scope, new(true, [reused]), Time.AddMinutes(1));
        Assert.Throws<ArgumentException>(() => Store.Merge(Scope, Before.Ip, reused.Ip, Time.AddMinutes(2)));
        Assert.Equal("confirmed_same_device", Store.Merge(Scope, Before.Mac!, reused.Mac!, Time.AddMinutes(2)).Association!.Status);
    }

    [Fact]
    public void ConcurrentDevicesCannotBeMerged()
    {
        Store.Apply(Scope, new(true, [Before, After]), Time);
        Assert.Throws<ArgumentException>(() => Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(1)));
        Assert.DoesNotContain(Store.ListAlerts(Scope), a => a.Kind == "identity_merged");
    }

    [Fact]
    public void InvalidOrOutOfScopeIdentitiesDoNotChangeBaseline()
    {
        Seed();
        var baseline = JsonSerializer.Serialize(Store.ListDevices(Scope));
        Assert.Throws<ArgumentException>(() => Store.Merge(Scope, Before.Ip, "192.168.88.21", Time.AddMinutes(2)));
        Assert.Throws<ArgumentException>(() => Store.Merge(Scope, After.Ip, After.Ip, Time.AddMinutes(2)));
        Assert.Equal(baseline, JsonSerializer.Serialize(Store.ListDevices(Scope)));
    }

    [Fact]
    public void AlertWriteFailureRollsBackTrustHistoryAndArchiveTogether()
    {
        Seed();
        var baseline = JsonSerializer.Serialize(Store.ListDevices(Scope));
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Db, Pooling = false }.ToString());
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = "CREATE TRIGGER reject_merge BEFORE INSERT ON monitor_alerts WHEN NEW.kind='identity_merged' BEGIN SELECT RAISE(ABORT,'injected write failure'); END;";
        command.ExecuteNonQuery();
        Assert.Throws<SqliteException>(() => Store.Merge(Scope, Before.Ip, After.Ip, Time.AddMinutes(2)));
        Assert.Equal(baseline, JsonSerializer.Serialize(Store.ListDevices(Scope)));
    }

    [Fact]
    public void PreviouslyRecordedRotationWithoutAssociationIsRepairedOnNextScan()
    {
        Seed(false);
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Db, Pooling = false }.ToString()))
        {
            db.Open();
            using var command = db.CreateCommand();
            command.CommandText = "UPDATE monitor_devices SET state_json=json_remove(state_json,'$.Association','$.MergedIntoId')";
            command.ExecuteNonQuery();
        }
        var update = Store.Apply(Scope, new(true, [After]), Time.AddMinutes(2));
        var alert = Assert.Single(update.Alerts, a => a.Kind == "identity_association");
        Assert.Equal("medium", alert.Priority);
        Assert.Contains($"之前的 {Before.Ip}", alert.Message);
        Assert.Contains($"monitor --merge {Before.Ip} {After.Ip}", alert.Message);
    }

}
