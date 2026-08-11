namespace LucentMist.Tools;

/// <summary>
/// 工具执行结果
/// </summary>
public record ToolResult
{
    public bool Success { get; init; } = true;
    public string Data { get; init; } = string.Empty;
    public string? Error { get; init; }
    public TimeSpan Duration { get; init; }

    public static ToolResult Ok(string data, TimeSpan duration) =>
        new() { Success = true, Data = data, Duration = duration };

    public static ToolResult Fail(string error, TimeSpan duration) =>
        new() { Success = false, Error = error, Duration = duration };
}

/// <summary>
/// 工具参数
/// </summary>
public class ToolArguments : Dictionary<string, string>
{
    public string GetOrDefault(string key, string defaultValue = "") =>
        TryGetValue(key, out var value) ? value : defaultValue;

    public int GetInt(string key, int defaultValue = 0) =>
        TryGetValue(key, out var value) && int.TryParse(value, out var i) ? i : defaultValue;

    public int[] GetIntArray(string key) =>
        TryGetValue(key, out var value)
            ? value.Split(',', StringSplitOptions.RemoveEmptyEntries)
                   .Select(s => int.TryParse(s.Trim(), out var p) ? p : -1)
                   .Where(p => p > 0)
                   .ToArray()
            : [];
}

/// <summary>
/// 工具接口 — 所有网络工具和 AI 工具的抽象
/// </summary>
public interface ITool
{
    /// <summary>工具名称</summary>
    string Name { get; }

    /// <summary>工具描述（供 LLM 理解）</summary>
    string Description { get; }

    /// <summary>参数定义</summary>
    ToolParameter[] Parameters { get; }

    /// <summary>执行工具</summary>
    Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default);
}

/// <summary>
/// 工具参数定义
/// </summary>
public record ToolParameter
{
    public string Name { get; init; } = string.Empty;
    public string Type { get; init; } = "string";
    public string Description { get; init; } = string.Empty;
    public bool Required { get; init; }
    public string? Default { get; init; }
}
