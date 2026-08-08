using LucentMist.Core.Models;

namespace LucentMist.Core.Interfaces;

/// <summary>
/// 会话管理接口
/// </summary>
public interface ISessionManager
{
    Task<Session> CreateAsync(string title = "");
    Task<Session?> GetAsync(string sessionId);
    Task<IEnumerable<Session>> ListAsync(int page = 1, int size = 20);
    Task UpdateAsync(Session session);
    Task DeleteAsync(string sessionId);
}

/// <summary>
/// Agent 会话
/// </summary>
public class Session
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Title { get; set; } = string.Empty;
    public string Model { get; init; } = "unknown";
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public int MessageCount { get; set; }
    public string? Summary { get; set; }
    public List<Message> Messages { get; init; } = [];
}

/// <summary>
/// 会话消息
/// </summary>
public record Message
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string SessionId { get; init; } = string.Empty;
    public string Role { get; init; } = "user"; // user / assistant / system / tool
    public string Content { get; init; } = string.Empty;
    public string? ToolCalls { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// 内存实现的会话管理器
/// </summary>
public class InMemorySessionManager : ISessionManager
{
    private readonly Dictionary<string, Session> _sessions = new();
    private readonly object _lock = new();

    public Task<Session> CreateAsync(string title = "")
    {
        var session = new Session
        {
            Title = string.IsNullOrWhiteSpace(title) ? "新会话" : title
        };
        lock (_lock) { _sessions[session.Id] = session; }
        return Task.FromResult(session);
    }

    public Task<Session?> GetAsync(string sessionId)
    {
        lock (_lock)
        {
            _sessions.TryGetValue(sessionId, out var session);
            return Task.FromResult(session);
        }
    }

    public Task<IEnumerable<Session>> ListAsync(int page = 1, int size = 20)
    {
        lock (_lock)
        {
            var result = _sessions.Values
                .OrderByDescending(s => s.UpdatedAt)
                .Skip((page - 1) * size)
                .Take(size)
                .ToList();
            return Task.FromResult<IEnumerable<Session>>(result);
        }
    }

    public Task UpdateAsync(Session session)
    {
        session.UpdatedAt = DateTime.UtcNow;
        lock (_lock) { _sessions[session.Id] = session; }
        return Task.CompletedTask;
    }

    public Task DeleteAsync(string sessionId)
    {
        lock (_lock) { _sessions.Remove(sessionId); }
        return Task.CompletedTask;
    }
}
