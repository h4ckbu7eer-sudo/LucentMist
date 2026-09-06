using LucentMist.Scanning.Monitoring;

namespace LucentMist.Scanning.Tests;

public sealed class NetworkMonitorTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"lmist-loop-{Guid.NewGuid():N}.db");
    private static readonly MonitorScope Scope = MonitorScope.Create("192.168.99.0/24", "80");
    private static readonly NetworkSnapshot Snapshot = new(true, [new("192.168.99.1", "00:11:22:33:44:55", "ZTE", "router", [80])]);
    public void Dispose()
    {
        foreach (var path in Directory.GetFiles(Path.GetDirectoryName(_path)!, Path.GetFileName(_path) + "*")) File.Delete(path);
    }

    [Fact]
    public async Task NextScanWaitsForBothPublishAndDelay_NoOverlapOrBacklog()
    {
        var events = new List<string>();
        var loop = new NetworkMonitor(new(_path), async ct =>
        {
            events.Add("scan");
            await Task.Yield();
            return Snapshot;
        }, (interval, ct) =>
        {
            Assert.Equal(TimeSpan.FromMinutes(30), interval);
            events.Add("delay");
            return Task.CompletedTask;
        });
        await loop.RunAsync(Scope, TimeSpan.FromMinutes(30), 2, async update =>
        {
            await Task.Yield();
            events.Add("publish");
        }, default);
        Assert.Equal(new[] { "scan", "publish", "delay", "scan", "publish" }, events);
    }

    [Fact]
    public async Task FailedScanRetainsBaselineAndFollowingRoundCanRecover()
    {
        var store = new MonitorStore(_path);
        store.Apply(Scope, Snapshot, DateTimeOffset.UtcNow);
        var calls = 0;
        var updates = new List<MonitorUpdate>();
        var loop = new NetworkMonitor(store, _ => ++calls == 1 ? throw new IOException("test") : Task.FromResult(Snapshot), (_, _) => Task.CompletedTask);
        await loop.RunAsync(Scope, TimeSpan.FromMinutes(1), 2, update => { updates.Add(update); return Task.CompletedTask; }, default);
        Assert.False(updates[0].Applied);
        Assert.DoesNotContain(updates[0].Alerts, a => a.Kind == "missing_device");
        Assert.True(updates[1].Applied);
        Assert.Empty(updates[1].Alerts);
    }

    [Fact]
    public async Task CancellationDoesNotCommitAnEmptySnapshot()
    {
        using var stop = new CancellationTokenSource();
        var store = new MonitorStore(_path);
        var now = DateTimeOffset.UtcNow;
        store.Apply(Scope, Snapshot, now);
        var loop = new NetworkMonitor(store, ct => { stop.Cancel(); ct.ThrowIfCancellationRequested(); return Task.FromResult(Snapshot); });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => loop.RunAsync(Scope, TimeSpan.FromMinutes(1), 1, _ => Task.CompletedTask, stop.Token));
        Assert.Equal(now, Assert.Single(store.ListDevices(Scope)).LastSeen);
        Assert.Empty(store.ListAlerts(Scope));
    }

    [Fact]
    public void SameDatabaseAndScopeCannotHaveTwoMonitorWriters()
    {
        using (NetworkMonitor.AcquireLease(_path, Scope))
            Assert.Throws<IOException>(() => NetworkMonitor.AcquireLease(_path, Scope));
        using var released = NetworkMonitor.AcquireLease(_path, Scope);
        Assert.True(released.CanWrite);
    }
}
