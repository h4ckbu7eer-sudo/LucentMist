using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning;

/// <summary>
/// 扫描任务持久化 — SQLite 存储。
/// 表结构对应 docs/03-数据库设计.md 的 scan_tasks。
/// </summary>
public class ScanStore : IScanTaskReader
{
    private readonly string _connectionString;

    public ScanStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _connectionString = $"Data Source={dbPath};Pooling=False";
        try
        {
            Initialize();
        }
        catch (SqliteException ex) when (IsCorruption(ex) && TryQuarantine(dbPath))
        {
            Initialize();
        }
    }

    private void Initialize()
    {
        using var conn = Open();
        EnsureHealthy(conn);
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id             TEXT PRIMARY KEY,
                target         TEXT NOT NULL,
                scan_type      TEXT NOT NULL DEFAULT 'ping',
                ports          TEXT NOT NULL DEFAULT '',
                status         TEXT NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'running', 'completed', 'failed')),
                created_at     TEXT NOT NULL,
                started_at     TEXT,
                heartbeat_at   TEXT,
                completed_at   TEXT,
                total_devices  INTEGER DEFAULT 0,
                result_json    TEXT,
                error_message  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scan_tasks_created ON scan_tasks(created_at);

            CREATE TABLE IF NOT EXISTS scan_audit (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id       TEXT NOT NULL,
                scan_task_id   TEXT,
                occurred_at    TEXT NOT NULL,
                target         TEXT NOT NULL,
                initiator      TEXT NOT NULL,
                scan_type      TEXT NOT NULL,
                status         TEXT NOT NULL
                               CHECK (status IN ('queued', 'completed', 'failed', 'rejected', 'canceled')),
                summary        TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_scan_audit_occurred ON scan_audit(occurred_at);
            CREATE INDEX IF NOT EXISTS idx_scan_audit_event ON scan_audit(event_id);
            """;
        cmd.ExecuteNonQuery();

        EnsurePortsColumn(conn);
        EnsureHeartbeatColumn(conn);
        EnsureStatusConstraint(conn);
        EnableWal(conn);
    }

    private static void EnableWal(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL;";
        cmd.ExecuteNonQuery();
    }

    private static void EnsureHealthy(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA quick_check;";
        var result = Convert.ToString(cmd.ExecuteScalar()) ?? "";
        if (!result.Equals("ok", StringComparison.OrdinalIgnoreCase))
            throw new SqliteException($"SQLite integrity check failed: {result}", 11);
    }

    private static bool IsCorruption(SqliteException ex) =>
        ex.SqliteErrorCode is 11 or 26;

    private static bool TryQuarantine(string dbPath)
    {
        var stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        try
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var source = dbPath + suffix;
                if (!File.Exists(source)) continue;
                var target = $"{source}.corrupt-{stamp}";
                if (File.Exists(target)) File.Delete(target);
                File.Move(source, target);
            }
            Console.Error.WriteLine(
                $"SQLite database was corrupt and has been quarantined: {dbPath}");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"Failed to quarantine corrupt SQLite database {dbPath}: {ex.Message}");
            return false;
        }
    }

    private static void EnsurePortsColumn(SqliteConnection conn) =>
        AddColumnIfMissing(conn, "ports", "TEXT NOT NULL DEFAULT ''");

    private static void EnsureHeartbeatColumn(SqliteConnection conn) =>
        AddColumnIfMissing(conn, "heartbeat_at", "TEXT");

    private static void EnsureStatusConstraint(SqliteConnection conn)
    {
        // SQLite cannot add a CHECK constraint to an existing column without
        // rebuilding the table. Triggers provide the same database-layer guard
        // for legacy databases while new databases receive the CHECK above.
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TRIGGER IF NOT EXISTS scan_tasks_valid_status_insert
            BEFORE INSERT ON scan_tasks
            FOR EACH ROW
            WHEN NEW.status NOT IN ('pending', 'running', 'completed', 'failed')
            BEGIN
                SELECT RAISE(ABORT, 'invalid scan task status');
            END;

            CREATE TRIGGER IF NOT EXISTS scan_tasks_valid_status_update
            BEFORE UPDATE OF status ON scan_tasks
            FOR EACH ROW
            WHEN NEW.status NOT IN ('pending', 'running', 'completed', 'failed')
            BEGIN
                SELECT RAISE(ABORT, 'invalid scan task status');
            END;
            """;
        cmd.ExecuteNonQuery();
    }

    private static void AddColumnIfMissing(
        SqliteConnection conn, string column, string definition)
    {
        if (HasColumn(conn, column)) return;

        try
        {
            using var migrate = conn.CreateCommand();
            migrate.CommandText =
                $"ALTER TABLE scan_tasks ADD COLUMN {column} {definition}";
            migrate.ExecuteNonQuery();
        }
        catch (SqliteException)
        {
            // Another process may have completed the same migration between the
            // existence check and ALTER TABLE. Re-check before surfacing errors.
            if (!HasColumn(conn, column)) throw;
        }
    }

    private static bool HasColumn(SqliteConnection conn, string column)
    {
        using var check = conn.CreateCommand();
        check.CommandText =
            "SELECT COUNT(*) FROM pragma_table_info('scan_tasks') WHERE name = $column";
        check.Parameters.AddWithValue("$column", column);
        return Convert.ToInt64(check.ExecuteScalar()) > 0;
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA busy_timeout=5000;";
        cmd.ExecuteNonQuery();
        return conn;
    }

    public async Task<ScanTaskRecord> CreateAsync(string target, string scanType, string ports)
    {
        var rec = new ScanTaskRecord { Target = target, ScanType = scanType, Ports = ports };
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_tasks (id, target, scan_type, ports, status, created_at, heartbeat_at)
            VALUES ($id, $target, $scan_type, $ports, 'pending', $created_at, $heartbeat_at)
            """;
        cmd.Parameters.AddWithValue("$id", rec.Id);
        cmd.Parameters.AddWithValue("$target", rec.Target);
        cmd.Parameters.AddWithValue("$scan_type", rec.ScanType);
        cmd.Parameters.AddWithValue("$ports", rec.Ports);
        cmd.Parameters.AddWithValue("$created_at", rec.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$heartbeat_at", rec.CreatedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
        return rec;
    }

    public async Task AppendAuditAsync(
        string eventId,
        string? scanTaskId,
        string target,
        string initiator,
        string scanType,
        string status,
        string summary = "",
        CancellationToken ct = default)
    {
        var validStatus = status is "queued" or "completed" or "failed" or "rejected" or "canceled";
        if (!validStatus) throw new ArgumentOutOfRangeException(nameof(status));

        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_audit
                (event_id, scan_task_id, occurred_at, target, initiator, scan_type, status, summary)
            VALUES
                ($eventId, $scanTaskId, $occurredAt, $target, $initiator, $scanType, $status, $summary)
            """;
        cmd.Parameters.AddWithValue("$eventId", CleanAuditValue(eventId, 64));
        cmd.Parameters.AddWithValue("$scanTaskId", (object?)scanTaskId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$occurredAt", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$target", CleanAuditValue(target, 253));
        cmd.Parameters.AddWithValue("$initiator", CleanAuditValue(initiator, 64));
        cmd.Parameters.AddWithValue("$scanType", CleanAuditValue(scanType, 32));
        cmd.Parameters.AddWithValue("$status", status);
        cmd.Parameters.AddWithValue("$summary", CleanAuditValue(summary, 256));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<ScanAuditRecord>> ListAuditAsync(
        int limit = 100,
        CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 1000);
        var records = new List<ScanAuditRecord>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, event_id, scan_task_id, occurred_at, target,
                   initiator, scan_type, status, summary
            FROM scan_audit
            ORDER BY id DESC
            LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$limit", limit);
        using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            records.Add(new ScanAuditRecord
            {
                Id = reader.GetInt64(0),
                EventId = reader.GetString(1),
                ScanTaskId = reader.IsDBNull(2) ? null : reader.GetString(2),
                OccurredAt = DateTime.Parse(
                    reader.GetString(3),
                    null,
                    System.Globalization.DateTimeStyles.RoundtripKind),
                Target = reader.GetString(4),
                Initiator = reader.GetString(5),
                ScanType = reader.GetString(6),
                Status = reader.GetString(7),
                Summary = reader.GetString(8),
            });
        }

        return records;
    }

    private static string CleanAuditValue(string? value, int maxLength)
    {
        var clean = new string((value ?? "")
            .Where(character => !char.IsControl(character))
            .ToArray());
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    public async Task<ScanTaskRecord?> GetAsync(string id, CancellationToken ct = default)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, target, scan_type, ports, status, created_at, started_at, completed_at,
                   total_devices, result_json, error_message
            FROM scan_tasks WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", id);

        using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return ReadRecord(reader);
    }

    public async Task<List<ScanTaskRecord>> ListAsync(int page, int size)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, target, scan_type, ports, status, created_at, started_at, completed_at,
                   total_devices, result_json, error_message
            FROM scan_tasks
            ORDER BY created_at DESC
            LIMIT $size OFFSET $offset
            """;
        cmd.Parameters.AddWithValue("$size", size);
        cmd.Parameters.AddWithValue("$offset", (page - 1) * size);

        var list = new List<ScanTaskRecord>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) list.Add(ReadRecord(reader));
        return list;
    }

    public async Task<bool> MarkRunningAsync(string id)
    {
        var changed = await UpdateAsync(
            id, "running", "status = 'pending'", startedAt: DateTime.UtcNow);
        if (changed) await MarkHeartbeatAsync(id);
        return changed;
    }

    public async Task MarkHeartbeatAsync(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE scan_tasks SET heartbeat_at = $heartbeat_at
            WHERE id = $id AND status IN ('pending', 'running')
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$heartbeat_at", DateTime.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<bool> MarkCompletedAsync(string id, int totalDevices, string resultJson)
    {
        return await UpdateAsync(
            id, "completed", "status = 'running'", totalDevices: totalDevices,
            resultJson: resultJson, completedAt: DateTime.UtcNow);
    }

    public async Task<bool> MarkFailedAsync(string id, string error)
    {
        return await UpdateAsync(
            id, "failed", "status IN ('pending', 'running')",
            errorMessage: error, completedAt: DateTime.UtcNow);
    }

    public async Task MarkStaleTasksFailedAsync(string error, TimeSpan olderThan)
    {
        var staleBefore = DateTime.UtcNow.Subtract(olderThan).ToString("O");
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE scan_tasks SET
                status = 'failed',
                completed_at = COALESCE(completed_at, $now),
                error_message = COALESCE(error_message, $error)
            WHERE status = 'running'
              AND COALESCE(heartbeat_at, started_at, created_at) < $stale_before
            """;
        cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$error", error);
        cmd.Parameters.AddWithValue("$stale_before", staleBefore);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<int> CleanupAsync(int retentionDays, bool vacuum = false)
    {
        var cutoff = DateTime.UtcNow.AddDays(-retentionDays).ToString("O");
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scan_tasks WHERE created_at < $cutoff";
        cmd.Parameters.AddWithValue("$cutoff", cutoff);
        var deleted = await cmd.ExecuteNonQueryAsync();

        if (vacuum && deleted > 0)
        {
            cmd.CommandText = "VACUUM;";
            await cmd.ExecuteNonQueryAsync();
        }

        return deleted;
    }

    private async Task<bool> UpdateAsync(string id, string status, string expectedStateSql,
        DateTime? startedAt = null, DateTime? completedAt = null,
        int? totalDevices = null, string? resultJson = null, string? errorMessage = null)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            UPDATE scan_tasks SET
                status = $status,
                started_at = COALESCE($started_at, started_at),
                completed_at = COALESCE($completed_at, completed_at),
                total_devices = COALESCE($total_devices, total_devices),
                result_json = COALESCE($result_json, result_json),
                error_message = COALESCE($error_message, error_message)
            WHERE id = $id AND {expectedStateSql}
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$status", status);
        cmd.Parameters.AddWithValue("$started_at", startedAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$completed_at", completedAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$total_devices", totalDevices ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$result_json", resultJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$error_message", errorMessage ?? (object)DBNull.Value);
        return await cmd.ExecuteNonQueryAsync() == 1;
    }

    private static ScanTaskRecord ReadRecord(SqliteDataReader reader)
    {
        return new ScanTaskRecord
        {
            Id = reader.GetString(0),
            Target = reader.GetString(1),
            ScanType = reader.GetString(2),
            Ports = reader.IsDBNull(3) ? "" : reader.GetString(3),
            Status = reader.GetString(4),
            CreatedAt = ParseOrUtc(reader.GetString(5)),
            StartedAt = reader.IsDBNull(6) ? null : ParseOrUtc(reader.GetString(6)),
            CompletedAt = reader.IsDBNull(7) ? null : ParseOrUtc(reader.GetString(7)),
            TotalDevices = reader.IsDBNull(8) ? 0 : reader.GetInt32(8),
            ResultJson = reader.IsDBNull(9) ? null : reader.GetString(9),
            ErrorMessage = reader.IsDBNull(10) ? null : reader.GetString(10),
        };
    }

    private static DateTime ParseOrUtc(string s) =>
        DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
            ? dt.ToUniversalTime() : DateTime.UtcNow;
}
