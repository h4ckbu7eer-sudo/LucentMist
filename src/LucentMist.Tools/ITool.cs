using System.Text.Json;

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
    public ToolArguments() : base(StringComparer.OrdinalIgnoreCase) { }

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

    /// <summary>
    /// Parse LLM tool arguments without requiring every JSON value to be a
    /// string. Numbers, booleans and primitive arrays are normalized to the
    /// string contract used by tools.
    /// </summary>
    public static ToolArguments ParseFlexible(string? input)
    {
        var result = new ToolArguments();
        if (string.IsNullOrWhiteSpace(input)) return result;

        try
        {
            using var document = JsonDocument.Parse(input);
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.String)
                return ParseFlexible(root.GetString());
            if (root.ValueKind != JsonValueKind.Object)
            {
                result["query"] = ElementText(root);
                return result;
            }

            foreach (var property in root.EnumerateObject())
                result[property.Name] = ElementText(property.Value);
            return result;
        }
        catch (JsonException)
        {
            result["query"] = input.Trim();
            return result;
        }
    }

    private static string ElementText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => string.Empty,
        JsonValueKind.Array => string.Join(",", value.EnumerateArray().Select(ElementText)),
        _ => value.GetRawText(),
    };
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
/// 标记工具的 target/host/ip 参数表示真实网络地址，ReAct 才应对其执行目标安全策略。
/// 例如 Sirius 的 target 是数据库主机 ID，不实现此接口。
/// </summary>
public interface INetworkTargetTool : ITool;

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
