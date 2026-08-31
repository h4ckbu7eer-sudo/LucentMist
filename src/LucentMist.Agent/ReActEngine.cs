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
    public int MaxCompletionDeferrals { get; set; } = 2;
    public List<ReActObservation> Observations { get; } = [];
    public List<string> ThoughtLog { get; } = [];
    public Func<ReActProgress, CancellationToken, Task>? Progress { get; set; }

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
        var completionDeferrals = 0;

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
            if (Progress != null) await Progress(new(round, step.Thought, null), ct);
            _logger.LogInformation("ReAct Step {Round}: Thought={Thought}, Action={Action}",
                round, step.Thought, step.Action);

            // 2. 检查是否是最终答案
            if (step.IsFinal)
            {
                bool CanCheck(string missing) => missing != "尚未检查目标端口暴露面" ||
                    _toolRegistry.Get("port_scan") != null || _toolRegistry.Get("vuln_scan") != null;
                var limitations = SecurityAnalysisEvidence.FindIncompleteChecks(userQuery, Observations).Where(CanCheck).ToArray();
                var incompleteChecks = SecurityAnalysisEvidence.FindIncompleteChecks(userQuery, Observations, includeFailedAttempts: false)
                    .Where(CanCheck)
                    .Concat(SecurityAnalysisEvidence.FindConclusionConflicts(step.ActionInput, Observations))
                    .Concat(limitations.Length > 0 && step.ActionInput.Contains("已确认安全", StringComparison.Ordinal)
                        ? new[] { "存在未检查或失败项，不能声称已确认安全；请给出有限评估和下一步" } : [])
                    .Concat(_toolRegistry.Get("get_my_ip") != null &&
                            System.Text.RegularExpressions.Regex.IsMatch(userQuery, @"我的\s*ip[？?。！!\s]*$", System.Text.RegularExpressions.RegexOptions.IgnoreCase) &&
                            !Observations.Any(item => item.ToolName == "get_my_ip" && item.Success)
                        ? new[] { "请先调用 get_my_ip 核实最新主接口，不仅依据注入快照回答" } : []).ToArray();
                if (incompleteChecks.Length > 0)
                {
                    if (completionDeferrals < MaxCompletionDeferrals)
                    {
                        completionDeferrals++;
                        await AddObservationAsync(new ReActObservation
                        {
                            Step = round,
                            ToolName = "analysis_completeness",
                            Input = "{}",
                            Result = "需要补查或修正：" + string.Join("；", incompleteChecks) +
                                     "。未做的检查请执行一次；已失败、版本未知或 DNS 不一致可以给出有限评估，不必反复探测。final_answer 应包含暴露面、TLS 风险、未知项与下一步；不能把失败当安全。",
                            Success = false,
                        }, ct);
                        continue;
                    }

                    return ReActResult.Ok(
                        SummarizeCurrentAnalysis(userQuery),
                        ThoughtLog,
                        Observations);
                }
                return ReActResult.Ok(limitations.Length > 0
                    ? SecurityAnalysisEvidence.LimitedAssessment(userQuery, Observations)
                    : SecurityAnalysisEvidence.WithVerifiedFacts(userQuery, step.ActionInput, Observations), ThoughtLog, Observations);
            }

            // 检测整个会话中的重复操作，而不只是上一条。JSON 属性顺序或数字/字符串
            // 表示不同也会归一化，避免 LLM 绕一轮后再次执行相同扫描。
            var operationKey = OperationKey(step.Action, step.ActionInput);
            if (step.Action == "invalid_response")
            {
                await AddObservationAsync(new ReActObservation
                {
                    Step = round,
                    ToolName = "response_contract",
                    Input = "{}",
                    Success = false,
                    Result = step.ActionInput,
                }, ct);
                continue;
            }
            if (Observations.Any(obs => obs.Success && OperationKey(obs.ToolName, obs.Input) == operationKey))
            {
                if ((completionDeferrals > 0 || SecurityAnalysisEvidence.FindIncompleteChecks(userQuery, Observations).Count > 0) &&
                    completionDeferrals < MaxCompletionDeferrals && round < MaxRounds)
                {
                    completionDeferrals++;
                    await AddObservationAsync(new ReActObservation
                    {
                        Step = round,
                        ToolName = "analysis_completeness",
                        Input = "{}",
                        Success = false,
                        Result = "该工具已完成，未重复执行。请依据已有证据直接修正最终结论，并说明未确认项或探测差异。",
                    }, ct);
                    continue;
                }
                _logger.LogWarning("检测到重复操作: {Action}({Input})，终止循环", step.Action, step.ActionInput);
                // 汇总所有已完成的观察结果作为最终结论
                var summary = SummarizeCurrentAnalysis(userQuery);
                return ReActResult.Ok(summary, ThoughtLog, Observations);
            }

            // 3. 执行工具
            var tool = _toolRegistry.Get(step.Action);
            if (tool == null)
            {
                await AddObservationAsync(new ReActObservation
                {
                    Step = round,
                    ToolName = step.Action,
                    Input = step.ActionInput,
                    Result = $"未知工具: {step.Action}。可用: {toolDefs}",
                    Success = false
                }, ct);
                continue;
            }

            // 4. 解析参数并调用工具
            var toolArgs = ToolArguments.ParseFlexible(step.ActionInput);
            if (tool is INetworkTargetTool)
                PromoteNetworkTargetAlias(toolArgs);
            if (step.Action == "vuln_scan")
                ReuseDiscoveredOpenPorts(toolArgs);

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
                        await AddObservationAsync(blocked, ct);
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
                var toolResult = await ExecuteWithArgumentRepairAsync(tool, toolArgs, ct);
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
                    Input = JsonSerializer.Serialize(toolArgs),
                    Result = toolResult.Success
                        ? toolResult.Data
                        : toolResult.Error ?? toolResult.Data,
                    Success = toolResult.Success
                };
                await AddObservationAsync(obs, ct);

                // 自动服务识别：port_scan 成功后，对每个开放端口调用 service_identify
                if (step.Action == "port_scan" && toolResult.Success)
                {
                    await AutoAnalyzeOpenPorts(toolResult.Data, round, ct);
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
                await AddObservationAsync(obs, ct);
            }
        }

        // 达到最大轮次，强制总结
        _logger.LogWarning("ReAct 达到最大轮次 {Max}，强制终止", MaxRounds);
        return ReActResult.Ok(
            SummarizeCurrentAnalysis(userQuery),
            ThoughtLog, Observations);
    }

    private string SummarizeCurrentAnalysis(string query)
    {
        if (SecurityAnalysisEvidence.RequiresSecurityConclusion(query))
            return SecurityAnalysisEvidence.LimitedAssessment(query, Observations);
        var missing = SecurityAnalysisEvidence.FindIncompleteChecks(query, Observations);
        var summary = SummarizeObservations(Observations);
        return missing.Count == 0 ? summary : summary + "\n尚未确认（不能判安全）：" + string.Join("；", missing);
    }

    internal static void PromoteNetworkTargetAlias(ToolArguments args)
    {
        if (!string.IsNullOrWhiteSpace(args.GetOrDefault("target"))) return;
        foreach (var alias in new[] { "host", "hostname", "ip", "address", "url", "query" })
        {
            var value = args.GetOrDefault(alias);
            if (string.IsNullOrWhiteSpace(value)) continue;
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
                value = uri.Host;
            args["target"] = value.Trim();
            return;
        }
    }

    private async Task<ToolResult> ExecuteWithArgumentRepairAsync(
        ITool tool,
        ToolArguments initialArgs,
        CancellationToken ct)
    {
        var args = initialArgs;
        var result = await tool.ExecuteAsync(args, ct);
        for (var retry = 0; retry < 2 && !result.Success; retry++)
        {
            if (!TryRepairArguments(tool, args, result.Error, out var repaired))
                break;

            _logger.LogDebug(
                "工具参数修正后重试: Tool={Tool}, Attempt={Attempt}, Error={Error}",
                tool.Name,
                retry + 1,
                result.Error);
            args = repaired;
            result = await tool.ExecuteAsync(args, ct);
        }
        return result;
    }

    internal static bool TryRepairArguments(
        ITool tool,
        ToolArguments current,
        string? error,
        out ToolArguments repaired)
    {
        repaired = new ToolArguments();
        foreach (var pair in current) repaired[pair.Key] = pair.Value;

        var changed = false;
        foreach (var parameter in tool.Parameters)
        {
            if (repaired.ContainsKey(parameter.Name)) continue;
            var aliases = parameter.Name switch
            {
                "target" => new[] { "host", "hostname", "ip", "address", "url", "query" },
                "port" => new[] { "ssl_port", "https_port", "service_port" },
                "timeout_ms" => new[] { "timeout", "timeoutMs" },
                _ => Array.Empty<string>(),
            };
            string? alias = null;
            foreach (var candidate in aliases)
            {
                if (repaired.TryGetValue(candidate, out var value) && !string.IsNullOrWhiteSpace(value))
                {
                    alias = candidate;
                    break;
                }
            }
            if (alias == null) continue;
            repaired[parameter.Name] = repaired[alias];
            changed = true;
        }

        if (repaired.TryGetValue("port", out var portText))
        {
            var digits = new string(portText.Trim().TakeWhile(char.IsDigit).ToArray());
            if (digits.Length > 0 && digits != portText)
            {
                repaired["port"] = digits;
                changed = true;
            }
        }

        // Retry only parameter-shaped failures and only when the argument set
        // actually changed. Network/TLS failures must not be repeated blindly.
        var parameterFailure = string.IsNullOrWhiteSpace(error) ||
            error.Contains("参数", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("目标", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("端口", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("required", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("invalid", StringComparison.OrdinalIgnoreCase);
        return changed && parameterFailure;
    }

    /// <summary>
    /// 自动服务识别：port_scan 成功后，对每个开放端口调用 service_identify
    /// </summary>
    private async Task AutoAnalyzeOpenPorts(
        string portScanResultJson,
        int round,
        CancellationToken ct)
    {
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
        var svcTool = _toolRegistry.Get("service_identify");
        if (svcTool != null && openPorts.Count > limit)
            _logger.LogWarning("自动服务识别超出上限 {Limit}，仅处理前 {Count} 个端口", limit, limit);

        var selectedPorts = openPorts.Take(limit).ToArray();
        var serviceObservations = new ReActObservation?[selectedPorts.Length];
        if (svcTool != null && selectedPorts.Length > 0)
        {
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
        }

        foreach (var observation in serviceObservations.OfType<ReActObservation>())
            await AddObservationAsync(observation, ct);

        if (openPorts.Contains(443))
            await AutoCheckTlsAsync(target, round, ct);
    }

    private void ReuseDiscoveredOpenPorts(ToolArguments args)
    {
        var target = args.GetOrDefault("target");
        foreach (var observation in Observations.AsEnumerable().Reverse())
        {
            if (!observation.Success || observation.ToolName != "port_scan") continue;
            try
            {
                using var document = JsonDocument.Parse(observation.Result);
                var root = document.RootElement;
                if (!root.TryGetProperty("target", out var resultTarget) ||
                    !string.Equals(resultTarget.GetString(), target, StringComparison.OrdinalIgnoreCase) ||
                    !root.TryGetProperty("openPorts", out var ports) ||
                    ports.ValueKind != JsonValueKind.Array ||
                    ports.GetArrayLength() == 0)
                    continue;

                args["open_ports"] = string.Join(",", ports.EnumerateArray()
                    .Select(port => port.GetInt32())
                    .Distinct()
                    .Order());
                return;
            }
            catch (JsonException)
            {
                // Ignore malformed historical observations and keep looking.
            }
        }
    }

    private async Task AutoCheckTlsAsync(string target, int round, CancellationToken ct)
    {
        var sslTool = _toolRegistry.Get("ssl_check");
        if (sslTool == null) return;

        var sslArgs = new ToolArguments
        {
            ["target"] = target,
            ["port"] = "443",
        };
        var auditEventId = Guid.NewGuid().ToString("N");
        await RecordAuditAsync(
            auditEventId,
            target,
            "ssl_check",
            "queued",
            "Agent 对已发现的 HTTPS 端口自动检查 TLS 证书",
            ct);
        var result = await ExecuteWithArgumentRepairAsync(sslTool, sslArgs, ct);
        await RecordAuditAsync(
            auditEventId,
            target,
            "ssl_check",
            result.Success ? "completed" : "failed",
            result.Success ? "Agent TLS 证书检查完成" : "Agent TLS 证书检查失败",
            ct);
        await AddObservationAsync(new ReActObservation
        {
            Step = round,
            ToolName = "ssl_check",
            Input = JsonSerializer.Serialize(sslArgs),
            Result = result.Success ? result.Data : result.Error ?? result.Data,
            Success = result.Success,
        }, ct);
    }

    private async Task AddObservationAsync(ReActObservation observation, CancellationToken ct)
    {
        Observations.Add(observation);
        if (Progress != null) await Progress(new(observation.Step, null, observation), ct);
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
    internal static string SummarizeObservations(List<ReActObservation> observations)
    {
        if (observations.Count == 0) return "未执行任何操作。";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("分析结果如下：");
        sb.AppendLine();

        var displayObservations = observations
            .Select((observation, index) => new { Observation = observation, Index = index })
            .GroupBy(item => OperationKey(item.Observation.ToolName, item.Observation.Input))
            .Select(group => group.LastOrDefault(item => item.Observation.Success) ?? group.Last())
            .OrderBy(item => item.Index)
            .Select(item => item.Observation);
        foreach (var obs in displayObservations)
        {
            sb.AppendLine($"  工具: {obs.ToolName}");
            sb.AppendLine($"  状态: {(obs.Success ? "成功" : "失败")}");

            if (!obs.Success)
            {
                sb.AppendLine($"  未确认: {obs.Result}");
                sb.AppendLine();
                continue;
            }

            // 只显示关键数据，不显示完整 JSON
            if (!string.IsNullOrEmpty(obs.Result))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(obs.Result);
                    var root = doc.RootElement;
                    if (obs.ToolName == "get_my_ip" && root.TryGetProperty("primaryIp", out var primaryIp))
                    {
                        var ip = primaryIp.GetString();
                        var name = root.TryGetProperty("primaryInterface", out var primaryName)
                            ? primaryName.GetString() : null;
                        sb.AppendLine(ip == null
                            ? "  未检测到可用物理主接口，不自动选择虚拟网卡作为主网络。"
                            : $"  本机主 IPv4: {ip}（接口: {name ?? "未注明"}）");
                        if (root.TryGetProperty("virtualInterfaceCount", out var count))
                            sb.AppendLine($"  另有 {count.GetInt32()} 个虚拟网卡（非主接口）。");
                    }
                    if (root.TryGetProperty("openPorts", out var ports))
                    {
                        var portList = ports.EnumerateArray().Select(p => p.GetInt32()).ToList();
                        sb.AppendLine(portList.Count > 0
                            ? $"  发现开放端口: {string.Join(", ", portList)}"
                            : "  无开放端口");
                    }
                    if (root.TryGetProperty("alive", out var alive))
                        sb.AppendLine($"  在线设备: {alive}");
                    if (root.TryGetProperty("deviceDetails", out var details) &&
                        details.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var device in details.EnumerateArray())
                        {
                            var ip = device.GetProperty("ip").GetString() ?? "未知";
                            var name = device.GetProperty("name").GetString() ?? "未广播";
                            var vendor = device.GetProperty("vendor").GetString() ?? "未知";
                            var model = device.GetProperty("model").GetString() ?? "未知";
                            sb.AppendLine($"  - {ip} | 名称: {name} | 厂商: {vendor} | 型号: {model}");
                        }
                    }
                    else if (root.TryGetProperty("devices", out var devices) &&
                             devices.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var device in devices.EnumerateArray())
                            sb.AppendLine($"  - {device.GetString() ?? "未知"}");
                    }
                    if (root.TryGetProperty("total", out var total))
                        sb.AppendLine($"  扫描范围: {total} 个 IP");
                    if (root.TryGetProperty("serviceName", out var svc) &&
                        root.TryGetProperty("port", out var svcPort))
                        sb.AppendLine($"  端口 {svcPort}: {svc}");
                    if (root.TryGetProperty("dnsSecurity", out var dns) &&
                        dns.ValueKind == JsonValueKind.Object)
                    {
                        var recursion = dns.TryGetProperty("recursionAssessment", out var recursionNode)
                            ? recursionNode.GetString() ?? "DNS 递归状态未知"
                            : "DNS 递归状态未知";
                        sb.AppendLine($"  DNS 判断: {recursion}");
                    }
                    if (obs.ToolName == "vuln_scan")
                        SecurityAnalysisEvidence.AppendVulnerabilitySummary(sb, root);
                    if (obs.ToolName == "ssl_check")
                        SecurityAnalysisEvidence.AppendTlsSummary(sb, root);
                }
                catch
                {
                    var shortResult = obs.Result.Length > 200 ? obs.Result[..200] + "..." : obs.Result;
                    sb.AppendLine($"  结果: {shortResult}");
                }
            }
            sb.AppendLine();
        }

        var dnsNote = SecurityAnalysisEvidence.DnsDisagreementNote(observations);
        if (dnsNote.Length > 0) sb.AppendLine(dnsNote);
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
public record ReActProgress(int Round, string? Thought, ReActObservation? Observation);

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
