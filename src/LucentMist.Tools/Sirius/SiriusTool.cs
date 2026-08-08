using System.Text.Json;

namespace LucentMist.Tools.Sirius;

/// <summary>
/// Sirius 漏洞扫描工具 — 供 Agent ReAct 引擎调用
/// </summary>
public class SiriusTool : ITool
{
    private readonly SiriusClient _client;

    public string Name => "sirius_scan";
    public string Description => "查询 Sirius 漏洞数据库：主机列表(summary)、主机详情(target)、扫描状态(status)";

    public ToolParameter[] Parameters => [
        new() { Name = "action", Type = "string", Description = "操作: summary/target/status", Required = true },
        new() { Name = "target", Type = "string", Description = "主机 ID（action=target 时必填）", Required = false }
    ];

    public SiriusTool(SiriusClient? client = null)
    {
        _client = client ?? new SiriusClient();
    }

    public async Task<ToolResult> ExecuteAsync(ToolArguments args)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var action = args.GetOrDefault("action", "summary");

        try
        {
            if (!await _client.CheckAvailabilityAsync())
                return ToolResult.Fail($"Sirius 不可用: {_client.ErrorMessage}", sw.Elapsed);

            object? data = action switch
            {
                "summary" => await _client.GetHostsAsync(),
                "target" => await _client.GetHostDetailAsync(args.GetOrDefault("target")),
                "status" => await _client.GetHostsAsync(),
                _ => null
            };

            if (data == null)
                return ToolResult.Fail("查询失败或无数据", sw.Elapsed);

            return ToolResult.Ok(JsonSerializer.Serialize(data), sw.Elapsed);
        }
        catch (Exception ex)
        {
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }
}
