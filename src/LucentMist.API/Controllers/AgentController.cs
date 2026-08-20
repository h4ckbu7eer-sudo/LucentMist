using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text.Json;
using LucentMist.Agent;
using LucentMist.Agent.LLM;
using LucentMist.Core.Networking;
using LucentMist.Scanning;
using LucentMist.Tools;
using Microsoft.AspNetCore.Mvc;

namespace LucentMist.API.Controllers;

[ApiController]
[Route("api/v1/agent")]
public class AgentController : ControllerBase
{
    private readonly ILLMProvider _llm;
    private readonly ToolRegistry _tools;
    private readonly AgentSessionStore _sessions;
    private readonly ILogger<AgentController> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public AgentController(
        ILLMProvider llm,
        ToolRegistry tools,
        AgentSessionStore sessions,
        ILogger<AgentController> logger,
        ILoggerFactory loggerFactory)
    {
        _llm = llm;
        _tools = tools;
        _sessions = sessions;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    /// <summary>
    /// ReAct 对话 — SSE 输出真实 thought / action / observation / message 事件。
    /// LLM 不可用时输出 error 事件，不再静默返回写死内容。
    /// </summary>
    [HttpPost("chat")]
    public async IAsyncEnumerable<string> Chat([FromBody] AgentChatRequest request, [EnumeratorCancellation] CancellationToken ct)
    {
        Response.ContentType = "text/event-stream";
        Response.Headers.CacheControl = "no-cache";
        Response.Headers.Connection = "keep-alive";

        if (string.IsNullOrWhiteSpace(request.Message))
        {
            yield return Sse("error", Json(new { content = "消息不能为空", done = true }));
            yield break;
        }

        var session = await _sessions.GetSessionAsync(request.SessionId ?? "")
            ?? await _sessions.CreateSessionAsync(
                "Agent 会话",
                Environment.GetEnvironmentVariable("LMIST_LLM_MODEL") ?? "qwen2.5:7b");
        await _sessions.AddMessageAsync(session.Id, "user", request.Message);
        yield return Sse("session", Json(new { sessionId = session.Id }));

        // 注入本机 IP，防止 LLM 猜测错误网段（与 CLI 保持一致）
        var message = InjectLocalNetworkInfo(request.Message);

        var systemPrompt = LoadSystemPrompt();

        var engine = new ReActEngine(_llm, _tools, systemPrompt, _loggerFactory.CreateLogger<ReActEngine>())
        {
            MaxRounds = 5,
        };

        ReActResult? result = null;
        string? runError = null;
        var canceled = false;
        try
        {
            result = await engine.RunAsync(message, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            canceled = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent 执行失败");
            runError = ex.Message;
        }

        if (canceled)
        {
            yield return Sse("error", Json(new { content = "连接已断开", done = true }));
            yield break;
        }

        if (runError != null)
        {
            await _sessions.AddMessageAsync(session.Id, "assistant", $"Agent 执行失败: {runError}");
            yield return Sse("error", Json(new { content = $"Agent 执行失败: {runError}", done = true }));
            yield break;
        }

        // 回放推理过程（thought → action+observation）
        for (int i = 0; i < engine.ThoughtLog.Count; i++)
        {
            await _sessions.AddMessageAsync(session.Id, "assistant", engine.ThoughtLog[i]);
            yield return Sse("thought", Json(new { content = engine.ThoughtLog[i] }));

            foreach (var obs in engine.ObservationsForRound(i + 1))
            {
                await _sessions.AddMessageAsync(
                    session.Id,
                    "tool",
                    obs.Result,
                    JsonSerializer.Serialize(new { tool = obs.ToolName, input = obs.Input, success = obs.Success }));
                yield return Sse("action", Json(new
                {
                    tool = obs.ToolName,
                    input = obs.Input,
                    success = obs.Success,
                }));
                yield return Sse("observation", Json(new { content = obs.Result }));
            }
        }

        var finalContent = result!.Success ? result.Answer : $"执行失败: {result.Error}";
        await _sessions.AddMessageAsync(session.Id, "assistant", finalContent);
        await _sessions.UpdateTitleAsync(session.Id, TitleFrom(request.Message));

        yield return Sse("message", Json(new
        {
            content = finalContent,
            done = true,
        }));
    }

    [HttpGet("sessions")]
    public async Task<IActionResult> ListSessions(
        [FromQuery] int page = 1, [FromQuery] int size = 20)
    {
        size = Math.Clamp(size, 1, 100);
        page = Math.Max(page, 1);
        var items = await _sessions.ListSessionsAsync(page, size);
        return Ok(new { page, size, items });
    }

    [HttpGet("sessions/{id}")]
    public async Task<IActionResult> GetSession(string id)
    {
        var session = await _sessions.GetSessionAsync(id);
        if (session == null)
            return NotFound(new { error = new { code = "NOT_FOUND", message = $"会话 {id} 不存在" } });

        var messages = await _sessions.GetMessagesAsync(id);
        return Ok(new { session, messages });
    }

    private static string TitleFrom(string message)
    {
        var text = message.Trim();
        return text.Length <= 20 ? text : text[..20] + "...";
    }

    /// <summary>
    /// 在用户消息前注入本机网卡信息，让 LLM 知道真实子网而非猜测 192.168.1.0/24
    /// </summary>
    private static string InjectLocalNetworkInfo(string message)
    {
        var entries = LocalNetworkInfo.GetEntries();
        if (entries.Count == 0) return message;

        var info = string.Join("; ", entries.Select(e =>
            $"{e.Ip}/{e.Prefix} (接口: {e.Name}, 网关: {e.Gateway})"));
        return $"[本机网络信息: {info}] {message}";
    }

    private string LoadSystemPrompt()
    {
        var path = FindSystemPrompt();
        if (path != null) return System.IO.File.ReadAllText(path);
        return "你是网络助手。输出 JSON: {thought, action, action_input}";
    }

    private static string? FindSystemPrompt()
    {
        var roots = new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory };
        foreach (var root in roots)
        {
            var dir = new DirectoryInfo(root);
            while (dir != null)
            {
                var candidate = Path.Combine(dir.FullName, "config", "prompts", "system_prompt.txt");
                if (System.IO.File.Exists(candidate)) return candidate;
                dir = dir.Parent;
            }
        }
        return null;
    }

    private static string Sse(string eventName, string data) =>
        $"event: {eventName}\ndata: {data}\n\n";

    private static string Json(object obj) =>
        JsonSerializer.Serialize(obj);
}

/// <summary>
/// 普通类而非 record 位置参数：确保 ASP.NET 大小写不敏感绑定（record 构造函数参数匹配区分大小写）
/// </summary>
public class AgentChatRequest
{
    [MaxLength(4096)]
    public string Message { get; set; } = "";
    public string? SessionId { get; set; }
}
