using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Threading.Channels;
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
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SessionLockEntry> SessionLocks = new();
    private static readonly Lazy<string> SystemPrompt = new(LoadSystemPromptCore);

    private readonly ILLMProvider _llm;
    private readonly ToolRegistry _tools;
    private readonly AgentSessionStore _sessions;
    private readonly ILogger<AgentController> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ScanStore _scanStore;

    public AgentController(
        ILLMProvider llm,
        ToolRegistry tools,
        AgentSessionStore sessions,
        ScanStore scanStore,
        ILogger<AgentController> logger,
        ILoggerFactory loggerFactory)
    {
        _llm = llm;
        _tools = tools;
        _sessions = sessions;
        _scanStore = scanStore;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    /// <summary>
    /// ReAct 对话 — SSE 输出真实 thought / action / observation / message 事件。
    /// LLM 不可用时输出 error 事件，不再静默返回写死内容。
    /// </summary>
    [HttpPost("chat")]
    public async Task Chat([FromBody] AgentChatRequest request, CancellationToken ct)
    {
        Response.ContentType = "text/event-stream";
        Response.Headers.CacheControl = "no-cache";
        Response.Headers.Connection = "keep-alive";
        Response.Headers["X-Accel-Buffering"] = "no";

        if (string.IsNullOrWhiteSpace(request.Message))
        {
            await SendEventAsync("error", new { content = "消息不能为空", done = true }, ct);
            return;
        }

        var session = await _sessions.GetSessionAsync(request.SessionId ?? "")
            ?? await _sessions.CreateSessionAsync(
                "Agent 会话",
                Environment.GetEnvironmentVariable("LMIST_LLM_MODEL")
                    ?? LLMProviderDefaults.ModelFor(Environment.GetEnvironmentVariable("LMIST_LLM_PROVIDER")));
        var sessionLock = await AcquireSessionLockAsync(session.Id, ct);
        try
        {
            var history = await _sessions.GetMessagesAsync(session.Id);
            await _sessions.AddMessageAsync(session.Id, "user", request.Message);
            await SendEventAsync("session", new { sessionId = session.Id }, ct);

            // 注入本机 IP，防止 LLM 猜测错误网段（与 CLI 保持一致）
            var contextualMessage = AgentConversationContext.Build(
                history.Select(item => new ChatMessage(item.Role, item.Content)), request.Message);
            var message = Environment.GetEnvironmentVariable("LMIST_INJECT_NETWORK_INFO") == "true"
                ? LocalNetworkInfo.InjectLocalNetworkInfo(contextualMessage)
                : contextualMessage;

            var systemPrompt = LoadSystemPrompt();
            var auditInitiator = Request.Headers["X-LMist-Initiator"].ToString()
                .Equals("web", StringComparison.OrdinalIgnoreCase)
                    ? "web-agent"
                    : "api-agent";

            using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var updates = Channel.CreateBounded<ReActProgress>(new BoundedChannelOptions(32)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait,
            });
            var engine = new ReActEngine(
                _llm,
                _tools,
                systemPrompt,
                _loggerFactory.CreateLogger<ReActEngine>(),
                new SqliteNetworkAuditSink(_scanStore, auditInitiator),
                auditInitiator)
            {
                MaxRounds = 5,
                Progress = (update, token) => updates.Writer.WriteAsync(update, token).AsTask(),
            };

            var run = RunEngineAsync();
            try
            {
                await foreach (var update in updates.Reader.ReadAllAsync(ct))
                {
                    if (update.Thought != null)
                    {
                        await _sessions.AddMessageAsync(session.Id, "assistant", update.Thought);
                        await SendEventAsync("thought", new { content = update.Thought }, ct);
                    }
                    if (update.Observation is { } obs)
                    {
                        var action = new { tool = obs.ToolName, input = obs.Input, success = obs.Success };
                        await _sessions.AddMessageAsync(session.Id, "tool", obs.Result, Json(action));
                        await SendEventAsync("action", action, ct);
                        await SendEventAsync("observation", new { content = obs.Result }, ct);
                    }
                }
                var result = await run;
                var finalContent = result.Success ? result.Answer : $"执行失败: {result.Error}";
                await _sessions.AddMessageAsync(session.Id, "assistant", finalContent);
                if (session.MessageCount == 0)
                    await _sessions.UpdateTitleAsync(session.Id, TitleFrom(request.Message));
                await SendEventAsync("message", new { content = finalContent, done = true }, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Disconnected clients cannot consume an error event.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Agent 执行失败");
                const string runError = "Agent 执行失败，请检查服务日志";
                await _sessions.AddMessageAsync(session.Id, "assistant", runError);
                await SendEventAsync("error", new { content = runError, done = true }, ct);
            }
            finally
            {
                runCancellation.Cancel();
                try { await run; }
                catch (OperationCanceledException) when (runCancellation.IsCancellationRequested) { }
                catch (Exception ex) { _logger.LogDebug(ex, "Agent run already reported failure"); }
            }

            async Task<ReActResult> RunEngineAsync()
            {
                try { return await engine.RunAsync(message, runCancellation.Token); }
                finally { updates.Writer.TryComplete(); }
            }
        }
        finally
        {
            sessionLock.Dispose();
        }
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

    private static string LoadSystemPrompt() => SystemPrompt.Value;

    private static string LoadSystemPromptCore()
    {
        var path = FindSystemPrompt();
        if (path != null)
        {
            try { return System.IO.File.ReadAllText(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
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

    private async Task SendEventAsync(string eventName, object data, CancellationToken ct)
    {
        await Response.WriteAsync(Sse(eventName, Json(data)), ct);
        await Response.Body.FlushAsync(ct);
    }

    private static string Json(object obj) =>
        JsonSerializer.Serialize(obj);

    private static async Task<SessionLockLease> AcquireSessionLockAsync(
        string sessionId,
        CancellationToken ct)
    {
        while (true)
        {
            var entry = SessionLocks.GetOrAdd(sessionId, _ => new SessionLockEntry());
            Interlocked.Increment(ref entry.ReferenceCount);
            if (SessionLocks.TryGetValue(sessionId, out var current) && ReferenceEquals(entry, current))
            {
                try
                {
                    await entry.Gate.WaitAsync(ct);
                    return new SessionLockLease(sessionId, entry);
                }
                catch
                {
                    ReleaseReference(sessionId, entry);
                    throw;
                }
            }

            ReleaseReference(sessionId, entry);
        }
    }

    private static void ReleaseReference(string sessionId, SessionLockEntry entry)
    {
        if (Interlocked.Decrement(ref entry.ReferenceCount) != 0) return;
        ((ICollection<KeyValuePair<string, SessionLockEntry>>)SessionLocks)
            .Remove(new KeyValuePair<string, SessionLockEntry>(sessionId, entry));
    }

    private sealed class SessionLockEntry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public int ReferenceCount;
    }

    private sealed class SessionLockLease(string sessionId, SessionLockEntry entry) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            entry.Gate.Release();
            ReleaseReference(sessionId, entry);
        }
    }
}

/// <summary>
/// 普通类而非 record 位置参数：确保 ASP.NET 大小写不敏感绑定（record 构造函数参数匹配区分大小写）
/// </summary>
public class AgentChatRequest
{
    [MaxLength(4096)]
    public string Message { get; set; } = "";
    [MaxLength(64)]
    public string? SessionId { get; set; }
}
