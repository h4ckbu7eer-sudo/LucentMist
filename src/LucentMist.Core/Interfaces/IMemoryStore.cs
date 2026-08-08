namespace LucentMist.Core.Interfaces;

/// <summary>
/// 记忆存储接口
/// </summary>
public interface IMemoryStore
{
    /// <summary>
    /// 存储短期记忆
    /// </summary>
    Task StoreAsync<T>(string key, T value, TimeSpan? ttl = null);

    /// <summary>
    /// 获取短期记忆
    /// </summary>
    Task<T?> RetrieveAsync<T>(string key) where T : class;

    /// <summary>
    /// 持久化长期记忆
    /// </summary>
    Task PersistAsync<T>(string key, T value);

    /// <summary>
    /// 查询长期记忆
    /// </summary>
    Task<IEnumerable<T>> QueryAsync<T>(string pattern) where T : class;

    /// <summary>
    /// 删除记忆
    /// </summary>
    Task DeleteAsync(string key);

    /// <summary>
    /// 清空所有记忆
    /// </summary>
    Task ClearAsync();
}

/// <summary>
/// 短期记忆（内存实现）
/// </summary>
public class ShortTermMemory : IMemoryStore
{
    private readonly Dictionary<string, (object Value, DateTime? Expiry)> _store = new();
    private readonly object _lock = new();

    public Task StoreAsync<T>(string key, T value, TimeSpan? ttl = null)
    {
        lock (_lock)
        {
            _store[key] = (value!, ttl.HasValue ? DateTime.UtcNow.Add(ttl.Value) : null);
        }
        return Task.CompletedTask;
    }

    public Task<T?> RetrieveAsync<T>(string key) where T : class
    {
        lock (_lock)
        {
            if (_store.TryGetValue(key, out var entry))
            {
                if (entry.Expiry.HasValue && DateTime.UtcNow > entry.Expiry.Value)
                {
                    _store.Remove(key);
                    return Task.FromResult<T?>(null);
                }
                return Task.FromResult<T?>((T?)entry.Value);
            }
        }
        return Task.FromResult<T?>(null);
    }

    public Task PersistAsync<T>(string key, T value)
    {
        // ShortTermMemory persists in-memory only;
        // LongTermMemory implementation uses SQLite
        return StoreAsync(key, value);
    }

    public Task<IEnumerable<T>> QueryAsync<T>(string pattern) where T : class
    {
        lock (_lock)
        {
            var results = _store
                .Where(kv => kv.Key.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                .Where(kv => !kv.Value.Expiry.HasValue || DateTime.UtcNow <= kv.Value.Expiry.Value)
                .Select(kv => (T)kv.Value.Value)
                .ToList();
            return Task.FromResult<IEnumerable<T>>(results);
        }
    }

    public Task DeleteAsync(string key)
    {
        lock (_lock)
        {
            _store.Remove(key);
        }
        return Task.CompletedTask;
    }

    public Task ClearAsync()
    {
        lock (_lock)
        {
            _store.Clear();
        }
        return Task.CompletedTask;
    }
}
