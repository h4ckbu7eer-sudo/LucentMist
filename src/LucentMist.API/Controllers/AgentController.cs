using System.Runtime.CompilerServices;
using System.Text.Json;
using LucentMist.Agent;
using LucentMist.Agent.LLM;
using LucentMist.Tools;
using Microsoft.AspNetCore.Mvc;

namespace LucentMist.API.Controllers;

[ApiController]
[Route("api/v1/agent")]
public class AgentController : ControllerBase
{
    private readonly ILLMProvider _llm;
    private readonly ToolRegistry _tools;
    private readonly ILogger<AgentController> _logger;

    public AgentController(ILLMProvider llm, ToolRegistry tools, ILogger<AgentController> logger)
    {
        _llm = llm;
        _tools = tools;
        _logger = logger;
    }

    /// <summary>
    /// ReAct 对话 — SSE 输出真实 thought / action / observation / message 事件。
    /// LLM 不可用时输出 error 事件，不再静默返回写死内容。
    /// </summary>
    [HttpPost("chat")]
    public async IAsyncEnumerable<string> Chat([FromBody] AgentChatRequest request, [EnumeratorCancellation] CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Message))
        {
            yield return Sse("error", Json(new { content = "消息不能为空", done = true }));
            yield break;
        }

        // 注入本机 IP，防止 LLM 猜测错误网段（与 CLI 保持一致）
        var message = InjectLocalNetworkInfo(request.Message);

        var systemPrompt = LoadSystemPrompt();

        var engine = new ReActEngine(_llm, _tools, systemPrompt, _logger as ILogger<ReActEngine>)
        {
            MaxRounds = 5,
        };

        ReActResult? result = null;
        string? runError = null;
        try
        {
            result = await engine.RunAsync(message, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent 执行失败");
            runError = ex.Message;
        }

        if (runError != null)
        {
            yield return Sse("error", Json(new { content = $"Agent 执行失败: {runError}", done = true }));
            yield break;
        }

        // 回放推理过程（thought → action+observation）
        for (int i = 0; i < engine.ThoughtLog.Count; i++)
        {
            yield return Sse("thought", Json(new { content = engine.ThoughtLog[i] }));

            if (i < engine.Observations.Count)
            {
                var obs = engine.Observations[i];
                yield return Sse("action", Json(new
                {
                    tool = obs.ToolName,
                    input = obs.Input,
                    success = obs.Success,
                }));
                yield return Sse("observation", Json(new { content = obs.Result }));
            }
        }

        yield return Sse("message", Json(new
        {
            content = result!.Success ? result.Answer : $"执行失败: {result.Error}",
            done = true,
        }));
    }

    /// <summary>
    /// 在用户消息前注入本机网卡信息，让 LLM 知道真实子网而非猜测 192.168.1.0/24
    /// </summary>
    private static string InjectLocalNetworkInfo(string message)
    {
        var localIPs = GetLocalIPs();
        if (localIPs.Count == 0) return message;

        var info = string.Join("; ", localIPs.Select(ip =>
            $"{ip.ip}/{ip.prefix} (接口: {ip.name}, 网关: {ip.gateway})"));
        return $"[本机网络信息: {info}] {message}";
    }

    private static List<(string name, string ip, int prefix, string gateway)> GetLocalIPs()
    {
        var results = new List<(string, string, int, string)>();
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
            var props = nic.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (ipv4 == null) continue;

            var ip = ipv4.Address.ToString();
            if (ip == "127.0.0.1") continue;

            var mask = ipv4.IPv4Mask?.ToString();
            var prefix = mask != null ? MaskToPrefix(mask) : 24;
            var gateway = props.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?.Address.ToString() ?? "未知";

            results.Add((nic.Name, ip, prefix, gateway));
        }
        return results;
    }

    private static int MaskToPrefix(string mask)
    {
        try
        {
            var parts = mask.Split('.').Select(int.Parse).ToArray();
            uint bits = 0;
            foreach (var p in parts) bits = (bits << 8) | (uint)p;
            var prefix = 0;
            while (bits > 0) { if ((bits & 0x80000000) != 0) prefix++; bits <<= 1; }
            return prefix;
        }
        catch { return 24; }
    }

    private string LoadSystemPrompt()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "prompts", "system_prompt.txt"),
            Path.Combine(Directory.GetCurrentDirectory(), "config", "prompts", "system_prompt.txt"),
            Path.Combine("config", "prompts", "system_prompt.txt"),
        };
        foreach (var p in candidates)
        {
            if (System.IO.File.Exists(p)) return System.IO.File.ReadAllText(p);
        }
        return "你是网络助手。输出 JSON: {thought, action, action_input}";
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
    public string Message { get; set; } = "";
    public string? SessionId { get; set; }
    public string Provider { get; set; } = "ollama";
    public string Model { get; set; } = "qwen2.5:7b";
    public string? Target { get; set; }
}
