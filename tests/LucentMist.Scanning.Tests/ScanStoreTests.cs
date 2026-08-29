using System.Reflection;
using LucentMist.Scanning;
using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Tests;

public class ScanStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(), $"lmist-scan-{Guid.NewGuid():N}.db");
    private readonly ScanStore _store;

    public ScanStoreTests()
    {
        _store = new ScanStore(_dbPath);
    }

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [Fact]
    public async Task Create_Then_Get_ReturnsPendingTask()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "tcp", "22,80");

        var loaded = await _store.GetAsync(rec.Id);

        Assert.NotNull(loaded);
        Assert.Equal("127.0.0.1", loaded!.Target);
        Assert.Equal("tcp", loaded.ScanType);
        Assert.Equal("22,80", loaded.Ports);
        Assert.Equal("pending", loaded.Status);
    }

    [Fact]
    public void NewSchema_DefinesStatusCheckConstraint()
    {
        using var conn = new SqliteConnection($"Data Source={_dbPath};Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scan_tasks'";

        var schema = Assert.IsType<string>(cmd.ExecuteScalar());
        Assert.Contains("CHECK (status IN", schema, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MarkRunning_Then_Completed_FlipsState()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "ping", "");

        await _store.MarkRunningAsync(rec.Id);
        var running = await _store.GetAsync(rec.Id);
        Assert.Equal("running", running!.Status);
        Assert.NotNull(running.StartedAt);

        await _store.MarkCompletedAsync(rec.Id, 3, "{\"alive\":3}");
        var done = await _store.GetAsync(rec.Id);
        Assert.Equal("completed", done!.Status);
        Assert.Equal(3, done.TotalDevices);
        Assert.NotNull(done.CompletedAt);
    }

    [Fact]
    public async Task MarkFailed_StoresError()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "udp", "53");

        await _store.MarkFailedAsync(rec.Id, "timeout");

        var loaded = await _store.GetAsync(rec.Id);
        Assert.Equal("failed", loaded!.Status);
        Assert.Equal("timeout", loaded.ErrorMessage);
    }

    [Fact]
    public async Task MarkFailed_DoesNotOverwriteCompletedTerminalState()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "tcp", "443");
        Assert.True(await _store.MarkRunningAsync(rec.Id));
        Assert.True(await _store.MarkCompletedAsync(rec.Id, 1, "{\"openPorts\":[443]}"));
        var completed = await _store.GetAsync(rec.Id);

        Assert.False(await _store.MarkFailedAsync(rec.Id, "shutdown"));

        var unchanged = await _store.GetAsync(rec.Id);
        Assert.Equal("completed", unchanged!.Status);
        Assert.Equal(completed!.CompletedAt, unchanged.CompletedAt);
        Assert.Equal("{\"openPorts\":[443]}", unchanged.ResultJson);
        Assert.Null(unchanged.ErrorMessage);
    }

    [Fact]
    public async Task MarkCompleted_DoesNotOverwriteFailedTerminalState()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "tcp", "443");
        Assert.True(await _store.MarkRunningAsync(rec.Id));
        Assert.True(await _store.MarkFailedAsync(rec.Id, "canceled"));
        var failed = await _store.GetAsync(rec.Id);

        Assert.False(await _store.MarkCompletedAsync(rec.Id, 1, "{}"));

        var unchanged = await _store.GetAsync(rec.Id);
        Assert.Equal("failed", unchanged!.Status);
        Assert.Equal(failed!.CompletedAt, unchanged.CompletedAt);
        Assert.Equal("canceled", unchanged.ErrorMessage);
        Assert.Null(unchanged.ResultJson);
    }

    [Fact]
    public async Task MarkStaleTasksFailedAsync_IgnoresRecentHeartbeat()
    {
        var rec = await _store.CreateAsync("10.0.0.1", "tcp", "80");
        await _store.MarkRunningAsync(rec.Id);

        await _store.MarkStaleTasksFailedAsync("stale", TimeSpan.FromMinutes(2));

        var loaded = await _store.GetAsync(rec.Id);
        Assert.Equal("running", loaded!.Status);
    }

    [Fact]
    public async Task MarkStaleTasksFailedAsync_FailsOnlyHeartbeatsOlderThanCutoff()
    {
        var recent = await _store.CreateAsync("10.0.0.1", "tcp", "80");
        var stale = await _store.CreateAsync("10.0.0.2", "tcp", "443");
        await _store.MarkRunningAsync(recent.Id);
        await _store.MarkRunningAsync(stale.Id);

        using (var conn = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE scan_tasks SET heartbeat_at = $old WHERE id = $id";
            cmd.Parameters.AddWithValue("$old", DateTime.UtcNow.AddMinutes(-3).ToString("O"));
            cmd.Parameters.AddWithValue("$id", stale.Id);
            cmd.ExecuteNonQuery();
        }

        await _store.MarkStaleTasksFailedAsync("stale", TimeSpan.FromMinutes(2));

        Assert.Equal("running", (await _store.GetAsync(recent.Id))!.Status);
        Assert.Equal("failed", (await _store.GetAsync(stale.Id))!.Status);
    }

    [Fact]
    public async Task MarkStaleTasksFailedAsync_DoesNotFailQueuedPendingTasks()
    {
        var rec = await _store.CreateAsync("10.0.0.1", "tcp", "80");

        using (var conn = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText =
                "UPDATE scan_tasks SET created_at = $old, heartbeat_at = $old WHERE id = $id";
            cmd.Parameters.AddWithValue("$old", DateTime.UtcNow.AddMinutes(-10).ToString("O"));
            cmd.Parameters.AddWithValue("$id", rec.Id);
            cmd.ExecuteNonQuery();
        }

        await _store.MarkStaleTasksFailedAsync("stale", TimeSpan.FromMinutes(2));

        Assert.Equal("pending", (await _store.GetAsync(rec.Id))!.Status);
    }

    [Fact]
    public async Task ListAsync_ReturnsNewestFirst()
    {
        var a = await _store.CreateAsync("10.0.0.1", "ping", "");
        var b = await _store.CreateAsync("10.0.0.2", "ping", "");

        var items = await _store.ListAsync(1, 10);

        Assert.Equal(b.Id, items[0].Id);
        Assert.Equal(a.Id, items[1].Id);
    }

    [Fact]
    public async Task ExistingSchema_WithoutPorts_IsMigrated()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"lmist-migrate-{Guid.NewGuid():N}.db");
        try
        {
            using (var conn = new SqliteConnection($"Data Source={dbPath};Pooling=False"))
            {
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    CREATE TABLE scan_tasks (
                        id             TEXT PRIMARY KEY,
                        target         TEXT NOT NULL,
                        scan_type      TEXT NOT NULL DEFAULT 'ping',
                        status         TEXT NOT NULL DEFAULT 'pending',
                        created_at     TEXT NOT NULL,
                        started_at     TEXT,
                        completed_at   TEXT,
                        total_devices  INTEGER DEFAULT 0,
                        result_json    TEXT,
                        error_message  TEXT
                    );
                    """;
                cmd.ExecuteNonQuery();
            }

            var store = new ScanStore(dbPath);
            var rec = await store.CreateAsync("127.0.0.1", "ping", "1-100");

            Assert.Equal("1-100", rec.Ports);
            var loaded = await store.GetAsync(rec.Id);
            Assert.Equal("1-100", loaded!.Ports);
        }
        finally
        {
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }

    [Fact]
    public async Task ExistingSchema_RejectsInvalidStatusThroughMigrationTrigger()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"lmist-status-{Guid.NewGuid():N}.db");
        try
        {
            CreateLegacySchema(dbPath);
            var store = new ScanStore(dbPath);
            var rec = await store.CreateAsync("127.0.0.1", "ping", "");

            using var conn = new SqliteConnection($"Data Source={dbPath};Pooling=False");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE scan_tasks SET status = 'unknown' WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", rec.Id);

            var ex = Assert.Throws<SqliteException>(() => cmd.ExecuteNonQuery());
            Assert.Contains("invalid scan task status", ex.Message);
            Assert.Equal("pending", (await store.GetAsync(rec.Id))!.Status);
        }
        finally
        {
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }

    [Fact]
    public void Open_SetsBusyTimeout()
    {
        var method = typeof(ScanStore).GetMethod("Open", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);

        using var conn = (SqliteConnection)method!.Invoke(_store, null)!;
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA busy_timeout;";

        Assert.Equal(5000, Convert.ToInt64(cmd.ExecuteScalar()));
    }

    [Fact]
    public async Task CleanupAsync_DeletesOldCompletedScans()
    {
        var rec = await _store.CreateAsync("127.0.0.1", "tcp", "80");
        await _store.MarkRunningAsync(rec.Id);
        await _store.MarkCompletedAsync(rec.Id, 1, "{}");

        using (var conn = new SqliteConnection($"Data Source={_dbPath};Pooling=False"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE scan_tasks SET created_at = $old WHERE id = $id";
            cmd.Parameters.AddWithValue("$old", DateTime.UtcNow.AddDays(-91).ToString("O"));
            cmd.Parameters.AddWithValue("$id", rec.Id);
            cmd.ExecuteNonQuery();
        }

        var deleted = await _store.CleanupAsync(90);

        Assert.Equal(1, deleted);
        Assert.Null(await _store.GetAsync(rec.Id));
    }

    [Fact]
    public async Task AuditLog_StoresOnlyBoundedSummaryAndRejectsInvalidStatus()
    {
        var summary = "完成\n" + new string('x', 400);
        await _store.AppendAuditAsync(
            "event-1",
            "task-1",
            "192.168.1.10",
            "web",
            "tcp",
            "completed",
            summary);

        var item = Assert.Single(await _store.ListAuditAsync());
        Assert.Equal("event-1", item.EventId);
        Assert.Equal("task-1", item.ScanTaskId);
        Assert.Equal("web", item.Initiator);
        Assert.Equal("completed", item.Status);
        Assert.DoesNotContain('\n', item.Summary);
        Assert.True(item.Summary.Length <= 256);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _store.AppendAuditAsync(
                "event-2", null, "127.0.0.1", "cli", "ping", "unknown"));
    }

    private static void CreateLegacySchema(string dbPath)
    {
        using var conn = new SqliteConnection($"Data Source={dbPath};Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE scan_tasks (
                id             TEXT PRIMARY KEY,
                target         TEXT NOT NULL,
                scan_type      TEXT NOT NULL DEFAULT 'ping',
                status         TEXT NOT NULL DEFAULT 'pending',
                created_at     TEXT NOT NULL,
                started_at     TEXT,
                completed_at   TEXT,
                total_devices  INTEGER DEFAULT 0,
                result_json    TEXT,
                error_message  TEXT
            );
            """;
        cmd.ExecuteNonQuery();
    }
}
