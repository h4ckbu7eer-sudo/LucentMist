using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LucentMist.Agent.LLM;

/// <summary>
/// Claude API Provider — 通过 Anthropic Claude API 调用
/// </summary>
public class ClaudeProvider : ILLMProvider
{
    private readonly HttpClient _http;
    private readonly string _model;
    private readonly ILogger<ClaudeProvider> _logger;

    public string Name => "Claude";

    private const string BaseUrl = "https://api.anthropic.com/v1/";
    private const string ApiVersion = "2023-06-01";

    public ClaudeProvider(string apiKey, string model, ILogger<ClaudeProvider>? logger = null)
    {
        _http = new HttpClient { BaseAddress = new Uri(BaseUrl) };
        _http.DefaultRequestHeaders.Add("x-api-key", apiKey);
        _http.DefaultRequestHeaders.Add("anthropic-version", ApiVersion);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _model = string.IsNullOrEmpty(model) ? "claude-sonnet-4-6" : model;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeProvider>.Instance;
    }

    public async Task<string> ChatAsync(string systemPrompt, List<ChatMessage> history, CancellationToken ct = default)
    {
        var userMessages = history
            .Select(m => new { role = m.Role == "assistant" ? "assistant" : "user", content = m.Content })
            .ToList();

        var body = new
        {
            model = _model,
            max_tokens = 4096,
            system = systemPrompt,
            messages = userMessages
        };

        var response = await SendRequestAsync(body, ct);
        return response;
    }

    public async Task<ReActStep> ReActAsync(
        string systemPrompt, string userQuery,
        List<ReActObservation> observations, string toolDefinitions,
        CancellationToken ct = default)
    {
        var obsText = observations.Count > 0
            ? "\n\n之前的观察:\n" + string.Join("\n", observations.Select(o =>
                  $"- [{o.ToolName}] {o.Input} → {(o.Success ? "成功" : "失败")}: {o.Result}"))
            : "";

        var prompt = $@"{systemPrompt}

## 可用工具
{toolDefinitions}

## 用户问题
{userQuery}
{obsText}

请返回 JSON 格式的下一步行动：
{{""thought"": ""推理"", ""action"": ""工具名或final_answer"", ""action_input"": ""参数""}}";

        var body = new
        {
            model = _model,
            max_tokens = 4096,
            system = systemPrompt,
            messages = new[] { new { role = "user", content = prompt } }
        };

        var reply = await SendRequestAsync(body, ct);
        return ParseResponse(reply);
    }

    private async Task<string> SendRequestAsync(object body, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _http.PostAsync("messages", content, ct);
        response.EnsureSuccessStatusCode();

        var responseJson = await response.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(responseJson);

        var text = "";
        foreach (var block in doc.RootElement.GetProperty("content").EnumerateArray())
        {
            if (block.GetProperty("type").GetString() == "text")
            {
                text += block.GetProperty("text").GetString();
            }
        }

        _logger.LogDebug("Claude Chat: {Model} → {Length} chars", _model, text.Length);
        return text;
    }

    private ReActStep ParseResponse(string reply)
    {
        try
        {
            var jsonStart = reply.IndexOf('{');
            var jsonEnd = reply.LastIndexOf('}');
            if (jsonStart >= 0 && jsonEnd > jsonStart)
            {
                var json = reply[jsonStart..(jsonEnd + 1)];
                var doc = JsonDocument.Parse(json);
                var actionInput = doc.RootElement.TryGetProperty("action_input", out var ai)
                    ? ai.ValueKind switch
                    {
                        JsonValueKind.String => ai.GetString() ?? "",
                        JsonValueKind.Object => ai.GetRawText(),
                        _ => ai.ToString()
                    }
                    : "";

                return new ReActStep
                {
                    Thought = doc.RootElement.GetProperty("thought").GetString() ?? "",
                    Action = doc.RootElement.GetProperty("action").GetString() ?? "final_answer",
                    ActionInput = actionInput
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse Claude response");
        }

        return new ReActStep
        {
            Thought = "解析失败",
            Action = "final_answer",
            ActionInput = reply
        };
    }

    public void Dispose() => _http.Dispose();
}
