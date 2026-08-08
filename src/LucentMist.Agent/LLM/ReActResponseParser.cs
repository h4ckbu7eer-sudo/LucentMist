using System.Text.Json;
using System.Text.RegularExpressions;

namespace LucentMist.Agent.LLM;

/// <summary>
/// ReAct 响应解析器 — 将 LLM 原始输出解析为 ReActStep。
/// 支持：合法 JSON、Markdown 代码块、多行噪音、正则兜底。
/// </summary>
public static class ReActResponseParser
{
    /// <summary>
    /// 解析 LLM 响应文本，提取 Thought / Action / ActionInput
    /// </summary>
    public static ReActStep Parse(string reply)
    {
        // 去掉 markdown 代码块包裹
        reply = reply
            .Replace("```json", "").Replace("```", "")
            .Trim();

        if (string.IsNullOrWhiteSpace(reply))
        {
            return new ReActStep
            {
                Thought = "空响应",
                Action = "final_answer",
                ActionInput = ""
            };
        }

        // 尝试提取每一行中可能的 JSON
        foreach (var line in reply.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            var jsonStart = trimmed.IndexOf('{');
            var jsonEnd = trimmed.LastIndexOf('}');
            if (jsonStart < 0 || jsonEnd <= jsonStart) continue;

            var json = trimmed[jsonStart..(jsonEnd + 1)];
            var step = TryParseJson(json);
            if (step != null) return step;
        }

        // 整个文本作为 JSON 尝试
        var overallStart = reply.IndexOf('{');
        var overallEnd = reply.LastIndexOf('}');
        if (overallStart >= 0 && overallEnd > overallStart)
        {
            var json = reply[overallStart..(overallEnd + 1)];
            var step = TryParseJson(json);
            if (step != null) return step;
        }

        // 正则表达式兜底提取 thought / action / action_input
        return RegexFallback(reply);
    }

    private static ReActStep? TryParseJson(string json)
    {
        try
        {
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var action = root.TryGetProperty("action", out var ac) ? ac.GetString() ?? "" : "";
            var thought = root.TryGetProperty("thought", out var th) ? th.GetString() ?? "" : "";

            // 有 thought 但没有 action → 当作 final_answer
            if (string.IsNullOrEmpty(action) && !string.IsNullOrEmpty(thought))
            {
                return new ReActStep
                {
                    Thought = thought,
                    Action = "final_answer",
                    ActionInput = thought
                };
            }

            if (string.IsNullOrEmpty(action)) return null; // 缺少 action，尝试下一个

            // action_input: 兼容对象和字符串两种格式
            var actionInput = "";
            if (root.TryGetProperty("action_input", out var ai))
            {
                if (ai.ValueKind == JsonValueKind.String)
                    actionInput = ai.GetString() ?? "";
                else if (ai.ValueKind == JsonValueKind.Object)
                    actionInput = ai.GetRawText(); // 序列化回 JSON 字符串
                else
                    actionInput = ai.ToString();
            }

            return new ReActStep
            {
                Thought = thought,
                Action = action,
                ActionInput = actionInput
            };
        }
        catch
        {
            return null; // JSON 无效，尝试下一个
        }
    }

    private static ReActStep RegexFallback(string reply)
    {
        // 提取 thought
        var thoughtMatch = Regex.Match(reply, @"""thought""\s*:\s*""([^""]+)""");
        var actionMatch = Regex.Match(reply, @"""action""\s*:\s*""([^""]+)""");
        var inputMatch = Regex.Match(reply, @"""action_input""\s*:\s*""(.+?)""\s*[}\]]");

        if (actionMatch.Success)
        {
            var thought = thoughtMatch.Success ? thoughtMatch.Groups[1].Value : "";
            var action = actionMatch.Groups[1].Value;
            var input = inputMatch.Success ? inputMatch.Groups[1].Value : "";

            // 如果 action_input 看起来是 JSON 对象，尝试提取
            if (string.IsNullOrEmpty(input))
            {
                var objMatch = Regex.Match(reply, @"""action_input""\s*:\s*(\{[^}]+\})");
                if (objMatch.Success)
                    input = objMatch.Groups[1].Value;
            }

            return new ReActStep
            {
                Thought = thought,
                Action = action,
                ActionInput = input
            };
        }

        // 完全无法解析 → 返回原始内容作为答案
        return new ReActStep
        {
            Thought = "解析失败，返回原始输出",
            Action = "final_answer",
            ActionInput = reply.Trim()
        };
    }
}
