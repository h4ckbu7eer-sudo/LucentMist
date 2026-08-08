using LucentMist.Agent.LLM;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging;

namespace LucentMist.Agent;

/// <summary>
/// Agent 服务 — 封装 ReAct 引擎的初始化和运行
/// </summary>
public class AgentService
{
    private readonly ILLMProvider _llm;
    private readonly ToolRegistry _toolRegistry;
    private readonly string _systemPrompt;
    private readonly ILogger<AgentService> _logger;

    public AgentService(
        ILLMProvider llm,
        ToolRegistry toolRegistry,
        string systemPrompt,
        ILogger<AgentService>? logger = null)
    {
        _llm = llm;
        _toolRegistry = toolRegistry;
        _systemPrompt = systemPrompt;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<AgentService>.Instance;
    }

    /// <summary>
    /// 运行 Agent 对话
    /// </summary>
    public async Task<ReActResult> ChatAsync(string message, CancellationToken ct = default)
    {
        var engine = new ReActEngine(_llm, _toolRegistry, _systemPrompt, _logger as ILogger<ReActEngine>)
        {
            MaxRounds = 10
        };

        return await engine.RunAsync(message, ct);
    }
}
