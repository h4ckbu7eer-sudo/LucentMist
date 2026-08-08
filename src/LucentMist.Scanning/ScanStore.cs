using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning;

/// <summary>
/// 扫描任务持久化 — SQLite 存储。
/// 表结构对应 docs/03-数据库设计.md 的 scan_tasks。
/// </summary>
public class ScanStore
{
    private readonly string _connectionString;

    public ScanStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(dbPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _connectionString = $"Data Source={dbPath};Pooling=False";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id             TEXT PRIMARY KEY,
                target         TEXT NOT NULL,
                scan_type      TEXT NOT NULL DEFAULT 'ping',
                ports          TEXT NOT NULL DEFAULT '',
                status         TEXT NOT NULL DEFAULT 'pending',
                created_at     TEXT NOT NULL,
                started_at     TEXT,
                completed_at   TEXT,
                total_devices  INTEGER DEFAULT 0,
                result_json    TEXT,
                error_message  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scan_tasks_created ON scan_tasks(created_at);
            """;
        cmd.ExecuteNonQuery();

        EnsurePortsColumn(conn);
    }

    private static void EnsurePortsColumn(SqliteConnection conn)
    {
        using var check = conn.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM pragma_table_info('scan_tasks') WHERE name = 'ports'";
        var hasPorts = Convert.ToInt64(check.ExecuteScalar()) > 0;
        if (hasPorts) return;

        using var migrate = conn.CreateCommand();
        migrate.CommandText = "ALTER TABLE scan_tasks ADD COLUMN ports TEXT NOT NULL DEFAULT ''";
        migrate.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    public async Task<ScanTaskRecord> CreateAsync(string target, string scanType, string ports)
    {
        var rec = new ScanTaskRecord { Target = target, ScanType = scanType, Ports = ports };
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO scan_tasks (id, target, scan_type, ports, status, created_at)
            VALUES ($id, $target, $scan_type, $ports, 'pending', $created_at)
            """;
        cmd.Parameters.AddWithValue("$id", rec.Id);
        cmd.Parameters.AddWithValue("$target", rec.Target);
        cmd.Parameters.AddWithValue("$scan_type", rec.ScanType);
        cmd.Parameters.AddWithValue("$ports", rec.Ports);
        cmd.Parameters.AddWithValue("$created_at", rec.CreatedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
        return rec;
    }

    public async Task<ScanTaskRecord?> GetAsync(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, target, scan_type, ports, status, created_at, started_at, completed_at,
                   total_devices, result_json, error_message
            FROM scan_tasks WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", id);

        using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
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

    public async Task MarkRunningAsync(string id)
    {
        await UpdateAsync(id, "running", startedAt: DateTime.UtcNow);
    }

    public async Task MarkCompletedAsync(string id, int totalDevices, string resultJson)
    {
        await UpdateAsync(id, "completed", totalDevices: totalDevices,
            resultJson: resultJson, completedAt: DateTime.UtcNow);
    }

    public async Task MarkFailedAsync(string id, string error)
    {
        await UpdateAsync(id, "failed", errorMessage: error, completedAt: DateTime.UtcNow);
    }

    private async Task UpdateAsync(string id, string status,
        DateTime? startedAt = null, DateTime? completedAt = null,
        int? totalDevices = null, string? resultJson = null, string? errorMessage = null)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE scan_tasks SET
                status = $status,
                started_at = COALESCE($started_at, started_at),
                completed_at = COALESCE($completed_at, completed_at),
                total_devices = COALESCE($total_devices, total_devices),
                result_json = COALESCE($result_json, result_json),
                error_message = COALESCE($error_message, error_message)
            WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$status", status);
        cmd.Parameters.AddWithValue("$started_at", startedAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$completed_at", completedAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$total_devices", totalDevices ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$result_json", resultJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$error_message", errorMessage ?? (object)DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
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
