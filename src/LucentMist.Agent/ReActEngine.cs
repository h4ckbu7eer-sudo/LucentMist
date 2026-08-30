using System.Text.Json;
using LucentMist.Agent.LLM;
using LucentMist.Core.Compliance;
using LucentMist.Core.Networking;
using LucentMist.Tools;
using Microsoft.Extensions.Logging;

namespace LucentMist.Agent;

/// <summary>
/// ReAct 推理引擎 — 推理(Thought) → 行动(Action) → 观察(Observation) 循环
/// </summary>
public class ReActEngine
{
    private readonly ILLMProvider _llm;
    private readonly ToolRegistry _toolRegistry;
    private readonly ILogger<ReActEngine> _logger;
    private readonly string _systemPrompt;
    private readonly INetworkAuditSink? _auditSink;
    private readonly string _auditInitiator;
    private readonly SemaphoreSlim _runGate = new(1, 1);

    public int MaxRounds { get; set; } = 10;
    public int MaxAutoIdentifyPorts { get; set; } = 20;
    public List<ReActObservation> Observations { get; } = [];
    public List<string> ThoughtLog { get; } = [];

    public IReadOnlyList<ReActObservation> ObservationsForRound(int round) =>
        Observations.Where(o => o.Step == round).ToList();

    public ReActEngine(
        ILLMProvider llm,
        ToolRegistry toolRegistry,
        string systemPrompt,
        ILogger<ReActEngine>? logger = null,
        INetworkAuditSink? auditSink = null,
        string auditInitiator = "agent")
    {
        _llm = llm;
        _toolRegistry = toolRegistry;
        _systemPrompt = systemPrompt;
        _auditSink = auditSink;
        _auditInitiator = auditInitiator;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<ReActEngine>.Instance;
    }

    /// <summary>
    /// 执行 ReAct 循环，处理用户查询
    /// </summary>
    public async Task<ReActResult> RunAsync(string userQuery, CancellationToken ct = default)
    {
        await _runGate.WaitAsync(ct);
        try
        {
            return await RunCoreAsync(userQuery, ct);
        }
        finally
        {
            _runGate.Release();
        }
    }

    private async Task<ReActResult> RunCoreAsync(string userQuery, CancellationToken ct)
    {
        Observations.Clear();
        ThoughtLog.Clear();

        _logger.LogInformation("ReAct 开始: Query={Query}, MaxRounds={Max}", userQuery, MaxRounds);
        var toolDefs = _toolRegistry.ExportForLLM();

        for (var round = 1; round <= MaxRounds; round++)
        {
            _logger.LogDebug("ReAct Round {Round}/{Max}", round, MaxRounds);

            // 1. 调用 LLM 推理
            ReActStep step;
            try
            {
                step = await _llm.ReActAsync(_systemPrompt, userQuery, Observations, toolDefs, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LLM 调用失败");
                return ReActResult.Fail("LLM 调用失败，请检查服务日志", ThoughtLog, Observations);
            }

            ThoughtLog.Add(step.Thought);
            _logger.LogInformation("ReAct Step {Round}: Thought={Thought}, Action={Action}",
                round, step.Thought, step.Action);

            // 2. 检查是否是最终答案
            if (step.IsFinal)
            {
                return ReActResult.Ok(step.ActionInput, ThoughtLog, Observations);
            }

            // 检测整个会话中的重复操作，而不只是上一条。JSON 属性顺序或数字/字符串
            // 表示不同也会归一化，避免 LLM 绕一轮后再次执行相同扫描。
            var operationKey = OperationKey(step.Action, step.ActionInput);
            if (Observations.Any(obs => OperationKey(obs.ToolName, obs.Input) == operationKey))
            {
                _logger.LogWarning("检测到重复操作: {Action}({Input})，终止循环", step.Action, step.ActionInput);
                // 汇总所有已完成的观察结果作为最终结论
                var summary = SummarizeObservations(Observations);
                return ReActResult.Ok(summary, ThoughtLog, Observations);
            }

            // 3. 执行工具
            var tool = _toolRegistry.Get(step.Action);
            if (tool == null)
            {
                Observations.Add(new ReActObservation
                {
                    Step = round,
                    ToolName = step.Action,
                    Input = step.ActionInput,
                    Result = $"未知工具: {step.Action}。可用: {toolDefs}",
                    Success = false
                });
                continue;
            }

            // 4. 解析参数并调用工具
            ToolArguments toolArgs;
            try
            {
                toolArgs = JsonSerializer.Deserialize<ToolArguments>(step.ActionInput)
                           ?? new ToolArguments();
            }
            catch
            {
                toolArgs = new ToolArguments { ["query"] = step.ActionInput };
            }

            try
            {
                var auditEventId = Guid.NewGuid().ToString("N");
                var target = tool is INetworkTargetTool
                    ? toolArgs.GetOrDefault("target")
                    : "";
                if (tool is INetworkTargetTool && string.IsNullOrWhiteSpace(target))
                    target = toolArgs.GetOrDefault("host");
                if (tool is INetworkTargetTool && string.IsNullOrWhiteSpace(target))
                    target = toolArgs.GetOrDefault("ip");
                if (tool is INetworkTargetTool && !string.IsNullOrWhiteSpace(target))
                {
                    var validation = await TargetGuard.ValidateAsync(target, ct);
                    if (!validation.IsAllowed || validation.RequiresPublicAuthorization)
                    {
                        var reason = validation.RequiresPublicAuthorization
                            ? "公网扫描未授权：请将目标 IP、CIDR 或域名加入 LMIST_ALLOWED_TARGETS 后重试"
                            : $"扫描目标被安全策略拒绝：{validation.Message}";
                        var blocked = new ReActObservation
                        {
                            Step = round,
                            ToolName = step.Action,
                            Input = step.ActionInput,
                            Result = reason,
                            Success = false,
                        };
                        Observations.Add(blocked);
                        await RecordAuditAsync(
                            auditEventId,
                            target,
                            step.Action,
                            "rejected",
                            validation.RequiresPublicAuthorization
                                ? "PUBLIC_TARGET_NOT_AUTHORIZED"
                                : validation.Code,
                            ct);
                        continue;
                    }
                }

                if (tool is INetworkTargetTool)
                {
                    await RecordAuditAsync(
                        auditEventId,
                        target,
                        step.Action,
                        "queued",
                        "Agent 工具调用已授权",
                        ct);
                }
                var toolResult = await tool.ExecuteAsync(toolArgs, ct);
                if (tool is INetworkTargetTool)
                {
                    await RecordAuditAsync(
                        auditEventId,
                        target,
                        step.Action,
                        toolResult.Success ? "completed" : "failed",
                        toolResult.Success ? "Agent 工具调用完成" : "Agent 工具调用失败",
                        ct);
                }
                var obs = new ReActObservation
                {
                    Step = round,
                    ToolName = step.Action,
                    Input = step.ActionInput,
                    Result = toolResult.Success
                        ? toolResult.Data
                        : toolResult.Error ?? toolResult.Data,
                    Success = toolResult.Success
                };
                Observations.Add(obs);

                // 自动服务识别：port_scan 成功后，对每个开放端口调用 service_identify
                if (step.Action == "port_scan" && toolResult.Success)
                {
                    await AutoIdentifyServices(toolResult.Data, toolArgs, round, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var obs = new ReActObservation
                {
                    Step = round,
                    ToolName = step.Action,
                    Input = step.ActionInput,
                    Result = ex.Message,
                    Success = false
                };
                Observations.Add(obs);
            }
        }

        // 达到最大轮次，强制总结
        _logger.LogWarning("ReAct 达到最大轮次 {Max}，强制终止", MaxRounds);
        return ReActResult.Ok(
            SummarizeObservations(Observations),
            ThoughtLog, Observations);
    }

    /// <summary>
    /// 自动服务识别：port_scan 成功后，对每个开放端口调用 service_identify
    /// </summary>
    private async Task AutoIdentifyServices(
        string portScanResultJson,
        ToolArguments portScanArgs,
        int round,
        CancellationToken ct)
    {
        var svcTool = _toolRegistry.Get("service_identify");
        if (svcTool == null) return;

        // 解析 port_scan 结果，提取 target 和 openPorts
        string target;
        List<int> openPorts;
        try
        {
            using var doc = JsonDocument.Parse(portScanResultJson);
            var r = doc.RootElement;
            target = r.GetProperty("target").GetString() ?? "";
            openPorts = r.TryGetProperty("openPorts", out var ports)
                ? ports.EnumerateArray().Select(p => p.GetInt32()).ToList()
                : [];
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse port scan result for auto service identification");
            return;
        }

        if (openPorts.Count == 0) return;

        _logger.LogInformation("自动服务识别: Target={Target}, Ports={Ports}",
            target, string.Join(",", openPorts));

        var limit = Math.Max(0, MaxAutoIdentifyPorts);
        if (limit == 0) return;
        if (openPorts.Count > limit)
            _logger.LogWarning("自动服务识别超出上限 {Limit}，仅处理前 {Count} 个端口", limit, limit);

        var selectedPorts = openPorts.Take(limit).ToArray();
        var serviceObservations = new ReActObservation?[selectedPorts.Length];
        await Parallel.ForEachAsync(
            Enumerable.Range(0, selectedPorts.Length),
            new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Min(4, selectedPorts.Length),
                CancellationToken = ct,
            },
            async (index, token) =>
            {
                var port = selectedPorts[index];
                try
                {
                    var svcArgs = new ToolArguments
                    {
                        ["target"] = target,
                        ["port"] = port.ToString()
                    };
                    var auditEventId = Guid.NewGuid().ToString("N");
                    await RecordAuditAsync(
                        auditEventId,
                        target,
                        "service_identify",
                        "queued",
                        "Agent 自动服务识别已授权",
                        token);
                    var svcResult = await svcTool.ExecuteAsync(svcArgs, token);
                    await RecordAuditAsync(
                        auditEventId,
                        target,
                        "service_identify",
                        svcResult.Success ? "completed" : "failed",
                        svcResult.Success ? "Agent 自动服务识别完成" : "Agent 自动服务识别失败",
                        token);

                    serviceObservations[index] = new ReActObservation
                    {
                        Step = round,
                        ToolName = "service_identify",
                        Input = JsonSerializer.Serialize(svcArgs),
                        Result = svcResult.Success
                            ? svcResult.Data
                            : svcResult.Error ?? svcResult.Data,
                        Success = svcResult.Success
                    };
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "自动服务识别失败: {Target}:{Port}", target, port);
                }
            });

        Observations.AddRange(serviceObservations.OfType<ReActObservation>());
    }

    private Task RecordAuditAsync(
        string eventId,
        string target,
        string operation,
        string status,
        string summary,
        CancellationToken ct) =>
        _auditSink?.RecordAsync(
            new NetworkAuditEvent(
                eventId,
                target,
                _auditInitiator,
                operation,
                status,
                summary),
            ct) ?? Task.CompletedTask;

    /// <summary>
    /// 汇总所有观察结果，生成可读的结论
    /// </summary>
    private static string SummarizeObservations(List<ReActObservation> observations)
    {
        if (observations.Count == 0) return "未执行任何操作。";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("分析结果如下：");
        sb.AppendLine();

        var seen = new HashSet<string>();
        foreach (var obs in observations)
        {
            var key = $"{obs.ToolName}|{obs.Input}";
            if (seen.Contains(key)) continue; // 跳过重复操作
            seen.Add(key);

            sb.AppendLine($"  工具: {obs.ToolName}");
            sb.AppendLine($"  状态: {(obs.Success ? "成功" : "失败")}");

            // 只显示关键数据，不显示完整 JSON
            if (obs.Success && !string.IsNullOrEmpty(obs.Result))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(obs.Result);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("openPorts", out var ports))
                    {
                        var portList = ports.EnumerateArray().Select(p => p.GetInt32()).ToList();
                        sb.AppendLine(portList.Count > 0
                            ? $"  发现开放端口: {string.Join(", ", portList)}"
                            : "  无开放端口");
                    }
                    if (root.TryGetProperty("alive", out var alive))
                        sb.AppendLine($"  在线设备: {alive}");
                    if (root.TryGetProperty("total", out var total))
                        sb.AppendLine($"  扫描范围: {total} 个 IP");
                    if (root.TryGetProperty("serviceName", out var svc) &&
                        root.TryGetProperty("port", out var svcPort))
                        sb.AppendLine($"  端口 {svcPort}: {svc}");
                }
                catch
                {
                    var shortResult = obs.Result.Length > 200 ? obs.Result[..200] + "..." : obs.Result;
                    sb.AppendLine($"  结果: {shortResult}");
                }
            }
            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }

    private static string OperationKey(string toolName, string input)
    {
        try
        {
            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(input);
            if (values != null)
            {
                var normalized = values
                    .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(pair => $"{pair.Key.ToLowerInvariant()}={pair.Value.ToString()}");
                return $"{toolName.ToLowerInvariant()}|{string.Join("&", normalized)}";
            }
        }
        catch (JsonException)
        {
            // 非 JSON 输入仍按去除首尾空白后的原文比较。
        }

        return $"{toolName.ToLowerInvariant()}|{input.Trim()}";
    }
}

/// <summary>
/// ReAct 执行结果
/// </summary>
public record ReActResult
{
    public bool Success { get; init; }
    public string Answer { get; init; } = string.Empty;
    public List<string> ThoughtLog { get; init; } = [];
    public List<ReActObservation> Observations { get; init; } = [];
    public string? Error { get; init; }

    public static ReActResult Ok(string answer, List<string> thoughts, List<ReActObservation> obs) =>
        new()
        {
            Success = true,
            Answer = answer,
            ThoughtLog = thoughts.ToList(),
            Observations = obs.ToList(),
        };

    public static ReActResult Fail(string error, List<string> thoughts, List<ReActObservation> obs) =>
        new()
        {
            Success = false,
            Error = error,
            ThoughtLog = thoughts.ToList(),
            Observations = obs.ToList(),
        };
}
