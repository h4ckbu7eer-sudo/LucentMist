using System.Collections.Concurrent;

namespace LucentMist.Tools;

/// <summary>
/// 工具注册表 — 管理所有注册的工具
/// </summary>
public class ToolRegistry
{
    private readonly ConcurrentDictionary<string, ITool> _tools = new();

    /// <summary>
    /// 注册工具
    /// </summary>
    public ToolRegistry Register(ITool tool)
    {
        _tools[tool.Name] = tool;
        return this;
    }

    /// <summary>
    /// 获取工具
    /// </summary>
    public ITool? Get(string name)
    {
        return _tools.TryGetValue(name, out var tool) ? tool : null;
    }

    /// <summary>
    /// 列出所有工具
    /// </summary>
    public IEnumerable<ITool> ListAll() => _tools.Values;

    /// <summary>
    /// 获取工具数量
    /// </summary>
    public int Count => _tools.Count;

    /// <summary>
    /// 导出工具定义（供 LLM 使用）
    /// </summary>
    public string ExportForLLM()
    {
        var toolDefs = _tools.Values.Select(t =>
        {
            var paramsDef = string.Join(", ", t.Parameters.Select(p =>
                $"{(p.Required ? "" : "[可选]")}{p.Name}:{p.Type} — {p.Description}"));
            return $"- {t.Name}: {t.Description}\n  参数: {paramsDef}";
        });

        return string.Join("\n", toolDefs);
    }
}
