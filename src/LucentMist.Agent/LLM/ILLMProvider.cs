namespace LucentMist.Agent.LLM;

/// <summary>
/// LLM Provider 接口 — 支持 Ollama / Claude / OpenAI 兼容端点（含 DeepSeek）
/// </summary>
public interface ILLMProvider
{
    /// <summary>Provider 名称</summary>
    string Name { get; }

    /// <summary>发送聊天消息</summary>
    Task<string> ChatAsync(string systemPrompt, List<ChatMessage> history, CancellationToken ct = default);

    /// <summary>ReAct 推理 — 给定当前状态，返回下一步行动</summary>
    Task<ReActStep> ReActAsync(
        string systemPrompt,
        string userQuery,
        List<ReActObservation> observations,
        string toolDefinitions,
        CancellationToken ct = default
    );
}

public static class LLMProviderDefaults
{
    public const string OllamaModel = "qwen2.5:7b";
    public const string ClaudeModel = "claude-sonnet-4-6";
    public const string OpenAIModel = "deepseek-chat";

    public static string ModelFor(string? provider) =>
        string.Equals(provider, "claude", StringComparison.OrdinalIgnoreCase)
            ? ClaudeModel
            : string.Equals(provider, "deepseek", StringComparison.OrdinalIgnoreCase)
                ? OpenAIModel
                : OllamaModel;
}

/// <summary>
/// 聊天消息
/// </summary>
public record ChatMessage(string Role, string Content);

/// <summary>
/// ReAct 步骤
/// </summary>
public record ReActStep
{
    public string Thought { get; init; } = string.Empty;
    public string Action { get; init; } = string.Empty;  // 工具名称，或 "final_answer"
    public string ActionInput { get; init; } = string.Empty; // JSON 参数
    public bool IsFinal => Action == "final_answer";
}

/// <summary>
/// ReAct 观察
/// </summary>
public record ReActObservation
{
    public int Step { get; init; }
    public string ToolName { get; init; } = string.Empty;
    public string Input { get; init; } = string.Empty;
    public string Result { get; init; } = string.Empty;
    public bool Success { get; init; }
}

/// <summary>
/// LLM Provider 工厂
/// </summary>
public static class LLMProviderFactory
{
    public static ILLMProvider Create(string provider, string model, string endpoint, string apiKey = "")
    {
        return provider.ToLower() switch
        {
            "ollama" => new OllamaProvider(endpoint, model),
            "claude" => new ClaudeProvider(apiKey, model),
            "deepseek" => new OpenAIProvider(apiKey, model, endpoint),
            _ => throw new ArgumentException($"不支持的 LLM Provider: {provider}")
        };
    }
}
