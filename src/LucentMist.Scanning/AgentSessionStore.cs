using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning;

/// <summary>Agent 会话记录。</summary>
public record AgentSessionRecord
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = "Agent 会话";
    public string Model { get; init; } = "";
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public int MessageCount { get; set; }
    public string? Summary { get; set; }
}

/// <summary>Agent 消息记录。</summary>
public record AgentMessageRecord
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; init; } = "";
    public string Role { get; init; } = "";
    public string Content { get; init; } = "";
    public string? ToolCalls { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Agent 会话持久化 — SQLite，表结构与 docs/03-数据库设计.md 对齐。
/// </summary>
public class AgentSessionStore
{
    private readonly string _connectionString;

    public AgentSessionStore(string dbPath)
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
            CREATE TABLE IF NOT EXISTS agent_sessions (
                id             TEXT PRIMARY KEY,
                title          TEXT NOT NULL DEFAULT 'Agent 会话',
                model          TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL,
                message_count  INTEGER DEFAULT 0,
                summary        TEXT
            );
            CREATE TABLE IF NOT EXISTS agent_messages (
                id          TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                tool_calls  TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_agent_messages_session
                ON agent_messages(session_id);
            """;
        cmd.ExecuteNonQuery();

        using (var wal = conn.CreateCommand())
        {
            wal.CommandText = "PRAGMA journal_mode=WAL;";
            wal.ExecuteNonQuery();
        }
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

    public async Task<AgentSessionRecord> CreateSessionAsync(string title, string model)
    {
        var rec = new AgentSessionRecord { Title = title, Model = model };
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO agent_sessions (id, title, model, created_at, updated_at, message_count)
            VALUES ($id, $title, $model, $created, $updated, 0)
            """;
        cmd.Parameters.AddWithValue("$id", rec.Id);
        cmd.Parameters.AddWithValue("$title", rec.Title);
        cmd.Parameters.AddWithValue("$model", rec.Model);
        cmd.Parameters.AddWithValue("$created", rec.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$updated", rec.UpdatedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
        return rec;
    }

    public async Task AddMessageAsync(
        string sessionId, string role, string content, string? toolCalls = null)
    {
        var msg = new AgentMessageRecord
        {
            SessionId = sessionId,
            Role = role,
            Content = content,
            ToolCalls = toolCalls,
        };

        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO agent_messages (id, session_id, role, content, tool_calls, created_at)
            VALUES ($id, $session, $role, $content, $tool_calls, $created)
            """;
        cmd.Parameters.AddWithValue("$id", msg.Id);
        cmd.Parameters.AddWithValue("$session", msg.SessionId);
        cmd.Parameters.AddWithValue("$role", msg.Role);
        cmd.Parameters.AddWithValue("$content", msg.Content);
        cmd.Parameters.AddWithValue("$tool_calls", msg.ToolCalls ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$created", msg.CreatedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();

        using var touch = conn.CreateCommand();
        touch.Transaction = tx;
        touch.CommandText = """
            UPDATE agent_sessions SET
                updated_at = $updated,
                message_count = (SELECT COUNT(*) FROM agent_messages WHERE session_id = $id)
            WHERE id = $id
            """;
        touch.Parameters.AddWithValue("$id", sessionId);
        touch.Parameters.AddWithValue("$updated", DateTime.UtcNow.ToString("O"));
        await touch.ExecuteNonQueryAsync();

        tx.Commit();
    }

    public async Task TouchAsync(string sessionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE agent_sessions SET
                updated_at = $updated,
                message_count = (SELECT COUNT(*) FROM agent_messages WHERE session_id = $id)
            WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", sessionId);
        cmd.Parameters.AddWithValue("$updated", DateTime.UtcNow.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task UpdateTitleAsync(string sessionId, string title)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agent_sessions SET title = $title WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", sessionId);
        cmd.Parameters.AddWithValue("$title", title);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<List<AgentSessionRecord>> ListSessionsAsync(int page, int size)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, title, model, created_at, updated_at, message_count, summary
            FROM agent_sessions
            ORDER BY updated_at DESC
            LIMIT $size OFFSET $offset
            """;
        cmd.Parameters.AddWithValue("$size", size);
        cmd.Parameters.AddWithValue("$offset", (page - 1) * size);

        var list = new List<AgentSessionRecord>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new AgentSessionRecord
            {
                Id = reader.GetString(0),
                Title = reader.GetString(1),
                Model = reader.GetString(2),
                CreatedAt = ParseOrUtc(reader.GetString(3)),
                UpdatedAt = ParseOrUtc(reader.GetString(4)),
                MessageCount = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
                Summary = reader.IsDBNull(6) ? null : reader.GetString(6),
            });
        }
        return list;
    }

    public async Task<AgentSessionRecord?> GetSessionAsync(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, title, model, created_at, updated_at, message_count, summary
            FROM agent_sessions WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", id);

        using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
        return new AgentSessionRecord
        {
            Id = reader.GetString(0),
            Title = reader.GetString(1),
            Model = reader.GetString(2),
            CreatedAt = ParseOrUtc(reader.GetString(3)),
            UpdatedAt = ParseOrUtc(reader.GetString(4)),
            MessageCount = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
            Summary = reader.IsDBNull(6) ? null : reader.GetString(6),
        };
    }

    public async Task<List<AgentMessageRecord>> GetMessagesAsync(string sessionId)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, session_id, role, content, tool_calls, created_at
            FROM agent_messages
            WHERE session_id = $id
            ORDER BY created_at
            """;
        cmd.Parameters.AddWithValue("$id", sessionId);

        var list = new List<AgentMessageRecord>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            list.Add(new AgentMessageRecord
            {
                Id = reader.GetString(0),
                SessionId = reader.GetString(1),
                Role = reader.GetString(2),
                Content = reader.GetString(3),
                ToolCalls = reader.IsDBNull(4) ? null : reader.GetString(4),
                CreatedAt = ParseOrUtc(reader.GetString(5)),
            });
        }
        return list;
    }

    private static DateTime ParseOrUtc(string s) =>
        DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
            ? dt.ToUniversalTime() : DateTime.UtcNow;
}
