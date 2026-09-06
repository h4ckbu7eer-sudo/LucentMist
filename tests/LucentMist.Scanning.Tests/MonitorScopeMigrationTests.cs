using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Tests;

public sealed class MonitorScopeMigrationTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"lmist-monitor-upgrade-{Guid.NewGuid():N}.db");
    private static readonly DateTimeOffset Time = DateTimeOffset.Parse("2026-09-07T00:00:00Z");
    private static readonly MonitorDevice Device = new("192.168.77.1", "00:11:22:33:44:55", "vendor", "router", [80]);
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.77.0/24", "22,80,443");
    public void Dispose() { foreach (var suffix in new[] { "", "-wal", "-shm" }) if (File.Exists(_path + suffix)) File.Delete(_path + suffix); }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = _path, Pooling = false }.ToString());
        db.Open();
        return db;
    }

    private void Seed(string ports, KnownDevice device, bool trusted = false)
    {
        using var db = Open();
        using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO monitor_state(scope,initialized,last_status) VALUES($scope,1,'completed');
            INSERT INTO monitor_devices(scope,device_id,ip,mac,vendor,first_seen,last_seen,known_ports,state_json)
                VALUES($scope,$id,$ip,$mac,'vendor',$first,$last,$ports,$json);
            INSERT INTO monitor_alerts(scope,occurred_at,kind,priority,ip,message)
                VALUES($scope,$last,'new_device','high',$ip,'historical event');
            INSERT INTO monitor_trust(scope,device_id) SELECT $scope,$id WHERE $trusted=1;
            """;
        foreach (var (name, value) in new (string, object)[] {
            ("$scope", Scope.Subnet + "|" + ports), ("$id", device.Device.Id), ("$ip", device.Device.Ip), ("$mac", device.Device.Mac!),
            ("$first", device.FirstSeen.ToString("O")), ("$last", device.LastSeen.ToString("O")),
            ("$ports", JsonSerializer.Serialize(device.Device.OpenPorts)), ("$json", JsonSerializer.Serialize(device)), ("$trusted", trusted ? 1 : 0) })
            command.Parameters.AddWithValue(name, value);
        command.ExecuteNonQuery();
    }

    [Fact]
    public void UpgradeMergesRecipes_PreservesTrustEventsAndPerPortEvidence_AcrossRestart()
    {
        _ = new MonitorStore(_path);
        Seed("80,443", new(Device with { OpenPorts = [80, 443] }, Time, Time, true, PortsObservedAt: Time, LastPortScanSucceeded: true), true);
        Seed("80", new(Device with { OpenPorts = [] }, Time.AddMinutes(1), Time.AddMinutes(1), true,
            PortsObservedAt: Time.AddMinutes(1), LastPortScanSucceeded: true));
        var store = new MonitorStore(_path);
        var actual = Assert.Single(store.ListDevices(Scope));
        Assert.True(actual.Trusted);
        Assert.Equal(Time, actual.FirstSeen);
        Assert.Equal(Time.AddMinutes(1), actual.LastSeen);
        Assert.Equal(new[] { 443 }, actual.Device.OpenPorts);
        Assert.False(actual.PortHistory![80].Open);
        Assert.Equal(Time, actual.PortHistory[443].At);
        Assert.Equal(new long[] { 2, 1 }, store.ListAlerts(Scope).Select(a => a.Id));
        var update = new MonitorStore(_path).Apply(MonitorScope.Create(Scope.Subnet, "80"), new(true, [Device]), Time.AddMinutes(2));
        Assert.False(update.BaselineCreated);
        Assert.Contains(update.Alerts, a => a.Kind == "port_added");
        Assert.DoesNotContain(update.Alerts, a => a.Kind is "new_device" or "port_not_observed");
        Assert.Equal(3, new MonitorStore(_path).ListAlerts(Scope).Length);
    }

    [Fact]
    public void MalformedLegacyStateRollsBackMigration_WithoutLosingOriginalRows()
    {
        _ = new MonitorStore(_path);
        Seed("80", new(Device, Time, Time, true), true);
        Seed("443", new(Device, Time, Time, true));
        using (var db = Open())
        using (var command = db.CreateCommand())
        {
            command.CommandText = "UPDATE monitor_devices SET state_json='invalid' WHERE scope LIKE '%|443'";
            command.ExecuteNonQuery();
        }
        Assert.Throws<JsonException>(() => new MonitorStore(_path));
        using var check = Open();
        using var count = check.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM monitor_devices WHERE instr(scope,'|')>0";
        Assert.Equal(2L, count.ExecuteScalar());
        count.CommandText = "SELECT COUNT(*) FROM monitor_trust WHERE instr(scope,'|')>0";
        Assert.Equal(1L, count.ExecuteScalar());
    }

    [Fact]
    public void DifferentRecipesShareTheSameProcessLease()
    {
        using var lease = NetworkMonitor.AcquireLease(_path, Scope);
        Assert.Throws<IOException>(() => NetworkMonitor.AcquireLease(_path, MonitorScope.Create(Scope.Subnet, "80")));
        // Lease files contain no data; keep cleanup scoped to this test's explicit path.
        var name = lease.Name;
        lease.Dispose();
        File.Delete(name);
    }
}
