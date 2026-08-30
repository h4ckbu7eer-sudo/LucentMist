using System.Text.Json;
using System.Text.Json.Nodes;
using LucentMist.Agent;
using LucentMist.Agent.LLM;
using LucentMist.Core.Networking;
using LucentMist.Scanning;
using LucentMist.Tools;
using LucentMist.Tools.Common;
using LucentMist.Tools.Reporting;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using LucentMist.Tools.Sirius;
using LucentMist.Tools.Vulnerability;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace LucentMist.CLI;

public class CliApp
{
    private static readonly ILogger Logger = LoggerFactory
        .Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning))
        .CreateLogger(nameof(CliApp));

    // 配置文件路径
    private static readonly string ConfigPath = FindFile("config/appsettings.json");

    public async Task<int> RunAsync(string[] args)
    {
        var command = args.Length > 0 ? args[0].ToLower() : "help";
        var commandArgs = args.Length > 0 ? args[1..] : [];
        async Task<int> ExecuteAsync() => command switch
        {
            "scan" => await ScanCommand(commandArgs),
            "ssl-check" => await SslCheckCommand(commandArgs),
            "os-fingerprint" => await OsFingerprintCommand(commandArgs),
            "vuln-scan" => await VulnScanCommand(commandArgs),
            "vuln-detail" => await VulnDetailCommand(commandArgs),
            "sirius" => await SiriusCommand(commandArgs),
            "sirius-scan" => await SiriusScanCommand(commandArgs),
            "report" => await ReportCommand(commandArgs),
            "agent" => await AgentCommand(commandArgs),
            "audit" => await AuditCommand(commandArgs),
            "backup" => BackupCommand(commandArgs),
            "restore" => RestoreCommand(commandArgs),
            "config" => await ConfigCommand(commandArgs),
            "status" => StatusCommand(),
            "help" => HelpCommand(),
            _ => UnknownCommand(command)
        };

        if (!TryGetAuditedTarget(command, commandArgs, out var target, out var scanType))
            return await ExecuteAsync();

        var store = CreateScanStore();
        var eventId = Guid.NewGuid().ToString("N");
        await store.AppendAuditAsync(
            eventId, null, target, "cli", scanType, "queued", "CLI 扫描请求已接收");
        try
        {
            var exitCode = await ExecuteAsync();
            await store.AppendAuditAsync(
                eventId,
                null,
                target,
                "cli",
                scanType,
                exitCode == 0 ? "completed" : "failed",
                exitCode == 0 ? "CLI 命令完成" : $"CLI 命令退出码 {exitCode}");
            return exitCode;
        }
        catch (OperationCanceledException)
        {
            await store.AppendAuditAsync(
                eventId, null, target, "cli", scanType, "canceled", "CLI 命令被取消");
            throw;
        }
        catch
        {
            await store.AppendAuditAsync(
                eventId, null, target, "cli", scanType, "failed", "CLI 命令异常终止");
            throw;
        }
    }

    private static ScanStore CreateScanStore() => new(
        Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db"));

    private static bool TryGetAuditedTarget(
        string command,
        string[] args,
        out string target,
        out string scanType)
    {
        target = "";
        scanType = command;
        if (command == "report")
        {
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i] == "--target" && i + 1 < args.Length) target = args[i + 1];
                else if (args[i].StartsWith("--target=", StringComparison.Ordinal))
                    target = args[i].Split('=', 2)[1];
            }
            return !string.IsNullOrWhiteSpace(target);
        }

        if (command is "ssl-check" or "os-fingerprint" or "vuln-scan" or "sirius-scan")
        {
            target = args.FirstOrDefault(argument => !argument.StartsWith('-')) ?? "";
            return !string.IsNullOrWhiteSpace(target);
        }

        if (command != "scan") return false;

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--ports" or "-p" or "--service" or "-s")
            {
                i++;
                continue;
            }
            if (!args[i].StartsWith('-'))
            {
                target = args[i];
                break;
            }
        }
        scanType = args.Contains("--udp", StringComparer.OrdinalIgnoreCase) ? "udp" : "scan";
        return !string.IsNullOrWhiteSpace(target);
    }

    // ========================================
    // 读取配置
    // ========================================
    private static (string provider, string model, string endpoint, string apiKey) ReadLLMConfig()
    {
        var provider = "ollama";
        var model = "qwen2.5:7b";
        var endpoint = "http://localhost:11434";
        var apiKey = "";
        var hasConfiguredModel = false;

        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("LucentMist", out var lm) &&
                    lm.TryGetProperty("LLM", out var llm))
                {
                    if (llm.TryGetProperty("Provider", out var p)) provider = p.GetString()!;
                    if (llm.TryGetProperty("Model", out var m) && !string.IsNullOrWhiteSpace(m.GetString()))
                    {
                        model = m.GetString()!;
                        hasConfiguredModel = true;
                    }
                    if (llm.TryGetProperty("OllamaEndpoint", out var oe)) endpoint = oe.GetString()!;
                    if (llm.TryGetProperty("ClaudeApiKey", out var ak)) apiKey = ak.GetString()!;
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Failed to read LLM config; using defaults");
        }

        provider = Environment.GetEnvironmentVariable("LMIST_LLM_PROVIDER") ?? provider;
        var environmentModel = Environment.GetEnvironmentVariable("LMIST_LLM_MODEL");
        if (!string.IsNullOrWhiteSpace(environmentModel))
        {
            model = environmentModel;
            hasConfiguredModel = true;
        }
        endpoint = Environment.GetEnvironmentVariable("LMIST_LLM_ENDPOINT") ?? endpoint;
        apiKey = Environment.GetEnvironmentVariable("LMIST_LLM_APIKEY") ?? apiKey;

        // deepseek 走 OpenAI 兼容端点；未显式配置 endpoint 时用官方默认
        if (string.Equals(provider, "deepseek", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(endpoint, "http://localhost:11434", StringComparison.OrdinalIgnoreCase))
        {
            endpoint = "https://api.deepseek.com/v1";
        }

        // deepseek 下若模型仍是 Ollama 默认（未显式指定），自动用 deepseek-chat
        if (string.Equals(provider, "deepseek", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(model, "qwen2.5:7b", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_LLM_MODEL")))
        {
            model = LLMProviderDefaults.OpenAIModel;
        }

        if (!hasConfiguredModel)
            model = LLMProviderDefaults.ModelFor(provider);

        return (provider, model, endpoint, apiKey);
    }

    private static void WriteLLMConfig(string? provider, string? model)
    {
        if (provider == null && model == null)
            return;

        try
        {
            var path = Path.GetFullPath(ConfigPath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var json = File.Exists(path) ? File.ReadAllText(path) : "{}";
            var root = JsonNode.Parse(json) as JsonObject ?? new JsonObject();
            var lucent = root["LucentMist"] as JsonObject;
            if (lucent is null)
            {
                lucent = new JsonObject();
                root["LucentMist"] = lucent;
            }

            var llm = lucent["LLM"] as JsonObject;
            if (llm is null)
            {
                llm = new JsonObject();
                lucent["LLM"] = llm;
            }

            if (provider != null)
                llm["Provider"] = provider;
            if (model != null)
                llm["Model"] = model;

            File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Failed to write LLM config to {Path}", ConfigPath);
        }
    }

    // ========================================
    // SCAN
    // ========================================
    private async Task<int> ScanCommand(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]请指定扫描目标[/]");
            return 1;
        }

        var target = "";
        var isUdp = false;
        var verbose = false;
        var tcpPorts = "";
        var svcPorts = "";
        var udpPorts = "53,123,161,500,514,1900";
        var positionals = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a == "--udp") isUdp = true;
            else if (a == "--verbose" || a == "-v") verbose = true;
            else if (a == "--ports" || a == "-p")
            {
                if (i + 1 < args.Length)
                {
                    tcpPorts = args[++i];
                    udpPorts = args[i];
                }
            }
            else if (a == "--service" || a == "-s")
            {
                if (i + 1 < args.Length)
                    svcPorts = args[++i];
            }
            else if (a.StartsWith("--ports=")) tcpPorts = a.Split('=', 2)[1];
            else if (a.StartsWith("-p=")) tcpPorts = a.Split('=', 2)[1];
            else if (a.StartsWith("--service=")) svcPorts = a.Split('=', 2)[1];
            else if (a.StartsWith("-s=")) svcPorts = a.Split('=', 2)[1];
            else if (!a.StartsWith("-")) positionals.Add(a);
        }

        target = positionals.FirstOrDefault() ?? "";
        if (string.IsNullOrWhiteSpace(target))
        {
            AnsiConsole.MarkupLine("[red]请指定扫描目标[/]");
            return 1;
        }
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;

        var lf = LoggerFactory.Create(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));

        AnsiConsole.Write(new Rule($"[teal]扫描目标: {Escape(target)}[/]"));

        // 1. Ping 扫描
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("正在扫描...", async _ =>
            {
                var tool = new PingScanTool(lf.CreateLogger<PingScanTool>());
                var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "2000" });

                AnsiConsole.WriteLine();
                if (!result.Success)
                {
                    AnsiConsole.MarkupLine($"[red]扫描失败: {Escape(result.Error!)}[/]");
                    return;
                }

                RenderPingResult(result.Data);
                AnsiConsole.MarkupLine($" [grey]耗时: {result.Duration.TotalSeconds:F1}s[/]");
            });

        // 2. TCP 端口扫描（--ports 指定时，且非 --udp）
        if (!isUdp && !string.IsNullOrEmpty(tcpPorts))
        {
            AnsiConsole.WriteLine();
            await RunTcpPortScan(target, tcpPorts, verbose, lf);
        }

        // 3. 服务识别（--service 指定时）
        if (!string.IsNullOrEmpty(svcPorts))
        {
            AnsiConsole.WriteLine();
            await RunServiceIdentify(target, svcPorts, lf);
        }

        // 4. UDP 扫描
        if (isUdp)
        {
            AnsiConsole.WriteLine();
            await RunUdpScan(target, udpPorts, verbose, lf);
        }

        return 0;
    }

    private static async Task RunTcpPortScan(string target, string ports, bool verbose, ILoggerFactory lf)
    {
        var tool = new PortScanTool(lf.CreateLogger<PortScanTool>());
        var result = await tool.ExecuteAsync(new ToolArguments
        {
            ["target"] = target,
            ["ports"] = ports,
            ["timeout_ms"] = "2000"
        });

        try
        {
            using var doc = JsonDocument.Parse(result.Data);
            var r = doc.RootElement;
            var scanned = r.GetProperty("totalScanned").GetInt32();
            var openSet = new HashSet<int>();
            if (r.TryGetProperty("openPorts", out var op))
                foreach (var p in op.EnumerateArray()) openSet.Add(p.GetInt32());

            var wellKnown = PortHelper.TcpServices;

            // 摘要
            var scanMode = verbose ? "TCP 端口扫描 (详细)" : "TCP 端口扫描";
            AnsiConsole.Write(new Rule($"[teal]{scanMode}: {Escape(target)}[/]"));
            var summary = new Table()
                .BorderColor(Color.Grey)
                .AddColumn("项目")
                .AddColumn("数值")
                .AddRow("扫描端口", $"{scanned}")
                .AddRow("开放端口", openSet.Count > 0 ? $"[green]{openSet.Count}[/]" : "[yellow]0[/]");
            AnsiConsole.Write(summary);

            // 开放端口表格
            if (openSet.Count > 0)
            {
                AnsiConsole.WriteLine();
                var table = new Table()
                    .BorderColor(Color.Green)
                    .AddColumn(new TableColumn("端口").Centered())
                    .AddColumn(new TableColumn("服务").Centered())
                    .AddColumn(new TableColumn("状态").Centered());

                foreach (var port in openSet.OrderBy(p => p))
                {
                    var name = wellKnown.GetValueOrDefault(port, "未知");
                    table.AddRow($"[yellow]{port}[/]", $"[green]{name}[/]", "[green]✅ 开放[/]");
                }
                AnsiConsole.Write(table);
            }

            // --verbose: 显示全部端口
            if (verbose)
            {
                AnsiConsole.WriteLine();
                var allTable = new Table()
                    .BorderColor(Color.Grey)
                    .AddColumn(new TableColumn("端口").Centered())
                    .AddColumn(new TableColumn("服务").Centered())
                    .AddColumn(new TableColumn("状态").Centered());

                var scannedPorts = ParsePortList(ports);
                foreach (var port in scannedPorts)
                {
                    var name = wellKnown.GetValueOrDefault(port, "未知");
                    var status = openSet.Contains(port) ? "[green]开放[/]" : "[red]关闭[/]";
                    allTable.AddRow($"[grey]{port}[/]", $"[grey]{name}[/]", status);
                }
                AnsiConsole.Write(allTable);
            }

            AnsiConsole.MarkupLine($" [grey]TCP 扫描耗时: {result.Duration.TotalSeconds:F1}s[/]");
        }
        catch
        {
            AnsiConsole.WriteLine(result.Data);
        }
    }

    private static async Task RunServiceIdentify(string target, string ports, ILoggerFactory lf)
    {
        var svcPorts = ParsePortList(ports);
        var tool = new ServiceIdentifyTool(lf.CreateLogger<ServiceIdentifyTool>());

        var rows = new List<(int port, string service, string banner, string? procName, int? pid, string? svcName, bool ok)>();
        var sw = System.Diagnostics.Stopwatch.StartNew();

        foreach (var port in svcPorts)
        {
            var result = await tool.ExecuteAsync(new ToolArguments
            {
                ["target"] = target,
                ["port"] = port.ToString(),
                ["timeout_ms"] = "3000"
            });

            try
            {
                using var doc = JsonDocument.Parse(result.Data);
                var r = doc.RootElement;
                var name = r.GetProperty("serviceName").GetString() ?? "?";
                var banner = r.TryGetProperty("banner", out var b) ? b.GetString() : null;
                var identified = r.TryGetProperty("identified", out var id) && id.GetBoolean();

                string? procName = null;
                int? pid = null;
                string? svcName = null;
                if (r.TryGetProperty("process", out var proc) && proc.ValueKind == JsonValueKind.Object)
                {
                    if (proc.TryGetProperty("processName", out var pn)) procName = pn.GetString();
                    if (proc.TryGetProperty("pid", out var pi) && pi.TryGetInt32(out var p)) pid = p;
                    if (proc.TryGetProperty("service", out var s)) svcName = s.GetString();
                }

                rows.Add((port, name, banner ?? "-", procName, pid, svcName, identified && banner != null));
            }
            catch
            {
                rows.Add((port, "error", result.Error ?? "未知错误", null, null, null, false));
            }
        }

        sw.Stop();

        AnsiConsole.Write(new Rule($"[teal]服务识别: {Escape(target)}[/]"));

        var table = new Table().BorderColor(Color.Grey)
            .AddColumn(new TableColumn("端口").Centered())
            .AddColumn(new TableColumn("服务").Centered())
            .AddColumn(new TableColumn("进程").Centered())
            .AddColumn(new TableColumn("PID"))
            .AddColumn(new TableColumn("Windows 服务"))
            .AddColumn(new TableColumn("Banner"));

        foreach (var (port, service, banner, procName, pid, svcName, ok) in rows)
        {
            var svcDisplay = ok ? $"[green]{service}[/]" : $"[yellow]{service}[/]";
            var procDisplay = procName != null ? $"[blue]{procName}[/]" : "[grey]-[/]";
            var pidDisplay = pid?.ToString() ?? "-";
            var winSvcDisplay = svcName != null ? $"[white]{svcName}[/]" : "[grey]-[/]";
            var banDisplay = ok
                ? $"[white]{Escape(banner.Length > 60 ? banner[..60] + "..." : banner)}[/]"
                : $"[grey]（无响应）[/]";
            table.AddRow($"[yellow]{port}[/]", svcDisplay, procDisplay, pidDisplay, winSvcDisplay, banDisplay);
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($" [grey]耗时: {sw.Elapsed.TotalSeconds:F1}s[/]");
    }

    private static async Task RunUdpScan(string target, string ports, bool verbose, ILoggerFactory lf)
    {
        var udpTool = new UdpScanTool(lf.CreateLogger<UdpScanTool>());
        var udpResult = await udpTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = target,
            ["ports"] = ports,
            ["timeout_ms"] = "3000"
        });

        try
        {
            using var doc = JsonDocument.Parse(udpResult.Data);
            var r = doc.RootElement;
            var scanned = r.GetProperty("totalScanned").GetInt32();
            var openSet = new HashSet<int>();
            if (r.TryGetProperty("openPorts", out var op))
                foreach (var p in op.EnumerateArray()) openSet.Add(p.GetInt32());

            var svcNames = PortHelper.UdpServices;

            // 摘要
            var scanMode = verbose ? "UDP 端口扫描 (详细)" : "UDP 端口扫描";
            AnsiConsole.Write(new Rule($"[teal]{scanMode}: {Escape(target)}[/]"));
            var summary = new Table()
                .BorderColor(Color.Grey)
                .AddColumn("项目")
                .AddColumn("数值")
                .AddRow("扫描端口", $"{scanned}")
                .AddRow("开放端口", openSet.Count > 0 ? $"[green]{openSet.Count}[/]" : "[yellow]0[/]");
            AnsiConsole.Write(summary);

            // 开放端口表格
            if (openSet.Count > 0)
            {
                AnsiConsole.WriteLine();
                var table = new Table()
                    .BorderColor(Color.Green)
                    .AddColumn(new TableColumn("端口").Centered())
                    .AddColumn(new TableColumn("服务").Centered())
                    .AddColumn(new TableColumn("状态").Centered());

                foreach (var port in openSet.OrderBy(p => p))
                {
                    var name = svcNames.GetValueOrDefault(port, "未知");
                    table.AddRow($"[yellow]{port}[/]", $"[green]{name}[/]", "[green]✅ 开放[/]");
                }
                AnsiConsole.Write(table);
            }

            // --verbose: 显示全部端口
            if (verbose)
            {
                AnsiConsole.WriteLine();
                var allTable = new Table()
                    .BorderColor(Color.Grey)
                    .AddColumn(new TableColumn("端口").Centered())
                    .AddColumn(new TableColumn("服务").Centered())
                    .AddColumn(new TableColumn("状态").Centered());

                var scannedPorts = ParsePortList(ports);
                foreach (var port in scannedPorts)
                {
                    var name = svcNames.GetValueOrDefault(port, "未知");
                    var status = openSet.Contains(port) ? "[green]开放[/]" : "[red]关闭[/]";
                    allTable.AddRow($"[grey]{port}[/]", $"[grey]{name}[/]", status);
                }
                AnsiConsole.Write(allTable);
            }

            AnsiConsole.MarkupLine($" [grey]UDP 扫描耗时: {udpResult.Duration.TotalSeconds:F1}s[/]");
        }
        catch
        {
            AnsiConsole.WriteLine(udpResult.Data);
        }
    }

    private static List<int> ParsePortList(string portsStr)
    {
        return PortHelper.ParsePorts(portsStr);
    }

    // ========================================
    // SSL-CHECK
    // ========================================
    private static async Task<int> SslCheckCommand(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]请指定目标域名或 IP[/]");
            return 1;
        }

        var target = args[0];
        var port = 443;
        var timeout = 5000;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--port" && i + 1 < args.Length)
            {
                if (!int.TryParse(args[++i], out port) || port is < 1 or > 65535)
                    return CliError("端口号必须是 1-65535 的整数");
            }
            else if (args[i].StartsWith("--port="))
            {
                if (!int.TryParse(args[i].Split('=', 2)[1], out port) || port is < 1 or > 65535)
                    return CliError("端口号必须是 1-65535 的整数");
            }
            else if (args[i] == "--timeout-ms" && i + 1 < args.Length)
            {
                if (!int.TryParse(args[++i], out timeout) || timeout <= 0)
                    return CliError("超时时间必须是正整数");
            }
            else if (args[i].StartsWith("--timeout-ms="))
            {
                if (!int.TryParse(args[i].Split('=', 2)[1], out timeout) || timeout <= 0)
                    return CliError("超时时间必须是正整数");
            }
        }
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;

        var lf = LoggerFactory.Create(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));
        var tool = new SslCertificateTool(lf.CreateLogger<SslCertificateTool>());

        AnsiConsole.Write(new Rule($"[teal]SSL 证书检查: {Escape(target)}:{port}[/]"));

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("正在获取证书...", async _ =>
            {
                var result = await tool.ExecuteAsync(new ToolArguments
                {
                    ["target"] = target,
                    ["port"] = port.ToString(),
                    ["timeout_ms"] = timeout.ToString()
                });

                if (!result.Success)
                {
                    AnsiConsole.MarkupLine($"[red]检查失败: {Escape(result.Error!)}[/]");
                    return;
                }

                try
                {
                    using var doc = JsonDocument.Parse(result.Data);
                    var r = doc.RootElement;

                    var subject = r.GetProperty("subject").GetString() ?? "?";
                    var issuer = r.GetProperty("issuer").GetString() ?? "?";
                    var notAfter = r.GetProperty("notAfter").GetString() ?? "?";
                    var days = r.GetProperty("daysRemaining").GetInt32();
                    var isExpired = r.GetProperty("isExpired").GetBoolean();
                    var thumbSha256 = r.GetProperty("thumbprintSha256").GetString() ?? "?";

                    var table = new Table()
                        .BorderColor(Color.Grey)
                        .AddColumn("项目")
                        .AddColumn("值")
                        .AddRow("目标", $"{Escape(target)}:{port}")
                        .AddRow("主题", Escape(subject))
                        .AddRow("颁发者", Escape(issuer))
                        .AddRow("过期时间", Escape(notAfter))
                        .AddRow("剩余天数", days > 0 ? $"[green]{days} 天[/]" : $"[red]{days} 天 (已过期)[/]")
                        .AddRow("状态", isExpired ? "[red]已过期[/]" : "[green]有效[/]")
                        .AddRow("SHA-256", Escape(thumbSha256[..16]) + "...");

                    if (r.TryGetProperty("san", out var san) && san.GetArrayLength() > 0)
                    {
                        var sanList = string.Join(", ", san.EnumerateArray().Select(s => s.GetString()).Take(5));
                        table.AddRow("SAN", Escape(sanList));
                    }

                    if (r.TryGetProperty("chain", out var chain))
                    {
                        table.AddRow("证书链", $"{chain.GetArrayLength()} 级");
                    }

                    AnsiConsole.WriteLine();
                    AnsiConsole.Write(table);
                    AnsiConsole.MarkupLine($" [grey]耗时: {result.Duration.TotalSeconds:F1}s[/]");
                }
                catch
                {
                    AnsiConsole.WriteLine(result.Data);
                }
            });

        return 0;
    }

    // ========================================
    // ========================================
    // REPORT
    // ========================================
    // ========================================
    // SIRIUS (子命令: summary / target / scan / status)
    // ========================================
    private static async Task<int> SiriusCommand(string[] args)
    {
        var sub = args.Length > 0 ? args[0].ToLower() : "help";
        var rest = args.Length > 1 ? args[1..] : [];

        using var client = new SiriusClient();
        if (!await client.CheckAvailabilityAsync())
        {
            AnsiConsole.MarkupLine($"[red]Sirius 不可用: {Escape(client.ErrorMessage)}[/]");
            return 1;
        }

        switch (sub)
        {
            case "summary":
                {
                    var hosts = await client.GetHostsAsync();
                    if (hosts == null || hosts.Count == 0) { AnsiConsole.MarkupLine("[yellow]无主机数据[/]"); return 0; }

                    AnsiConsole.Write(new Rule("[teal]Sirius 主机与漏洞汇总[/]"));
                    var t = new Table().BorderColor(Color.Grey)
                        .AddColumn(new TableColumn("主机ID").NoWrap())
                        .AddColumn(new TableColumn("IP").NoWrap())
                        .AddColumn("OS")
                        .AddColumn("端口")
                        .AddColumn("最近活跃");
                    foreach (var h in hosts.Take(20))
                    {
                        var portCount = h.Ports?.Count(p => p.State == "open") ?? 0;
                        var osShort = (h.OsVersion ?? "").Length > 30 ? (h.OsVersion ?? "")[..30] + "..." : (h.OsVersion ?? "");
                        t.AddRow(
                            $"[teal]{h.Hid}[/]",
                            $"[white]{Escape(h.Ip ?? "?")}[/]",
                            $"[grey]{Escape(h.Os ?? "?")} {Escape(osShort)}[/]",
                            portCount > 0 ? $"[green]{portCount} 开放[/]" : "[grey]—[/]",
                            $"[grey]{Escape(h.LastSeen ?? h.FirstSeen ?? "?")}[/]");
                    }
                    AnsiConsole.Write(t);
                    AnsiConsole.MarkupLine($"[grey]共 {hosts.Count} 台主机[/]");
                    return 0;
                }

            case "target":
                {
                    if (rest.Length == 0) { AnsiConsole.MarkupLine("[red]请指定主机 ID 或 IP[/]"); return 1; }
                    var query = rest[0];

                    // 从主机列表查找匹配的主机
                    var hosts = await client.GetHostsAsync();
                    var host = hosts?.FirstOrDefault(h => h.Hid == query || h.Ip == query);
                    if (host == null) { AnsiConsole.MarkupLine($"[yellow]未找到主机: {Escape(query)}[/]"); return 0; }

                    AnsiConsole.Write(new Rule($"[teal]主机: {Escape(host.Hid)}[/]"));
                    AnsiConsole.MarkupLine($"  IP: [teal]{Escape(host.Ip ?? "?")}[/]  OS: [white]{Escape(host.Os ?? "?")} {Escape((host.OsVersion ?? "").Length > 40 ? (host.OsVersion ?? "")[..40] : (host.OsVersion ?? ""))}[/]");
                    AnsiConsole.WriteLine();

                    if (host.Ports is { Count: > 0 })
                    {
                        var pt = new Table().BorderColor(Color.Grey).AddColumn("端口").AddColumn("协议").AddColumn("状态");
                        foreach (var p in host.Ports)
                        {
                            var stateColor = p.State?.ToLower() switch { "open" => "green", "closed" => "red", "filtered" => "yellow", _ => "grey" };
                            pt.AddRow($"[yellow]{p.Number}[/]", $"[white]{p.Protocol ?? "?"}[/]", $"[{stateColor}]{p.State ?? "?"}[/]");
                        }
                        AnsiConsole.Write(pt);
                    }
                    else { AnsiConsole.MarkupLine("[grey]无端口数据[/]"); }
                    return 0;
                }

            case "vuln":
                {
                    if (rest.Length == 0) { AnsiConsole.MarkupLine("[red]请指定 CVE 编号[/]"); return 1; }
                    var cveId = rest[0].ToUpper();
                    AnsiConsole.Write(new Rule($"[teal]Sirius CVE: {Escape(cveId)}[/]"));

                    var vulnData = await client.QueryVulnerabilitiesAsync(cve: cveId);
                    if (vulnData == null || vulnData.Value.ValueKind != JsonValueKind.Array || vulnData.Value.GetArrayLength() == 0)
                    { AnsiConsole.MarkupLine($"[yellow]未找到 {Escape(cveId)} 的漏洞数据[/]"); return 0; }

                    foreach (var v in vulnData.Value.EnumerateArray().Take(3))
                    {
                        var c = v.TryGetProperty("cve", out var cv) ? cv.GetString() ?? "?" : "?";
                        var n = v.TryGetProperty("name", out var nm) ? nm.GetString() ?? "" : "";
                        var r = v.TryGetProperty("risk", out var rk) ? rk.GetString() ?? "?" : "?";
                        var cvss = v.TryGetProperty("cvss", out var cs) && cs.TryGetDouble(out var sc) ? $"{sc:F1}" : "N/A";
                        var desc = v.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                        var fix = v.TryGetProperty("fix", out var fx) ? fx.GetString() ?? "" : "";

                        var riskColor = r.ToLower() switch { "critical" => "red", "high" => "yellow", "medium" => "green", _ => "grey" };
                        var tbl = new Table().BorderColor(Color.Grey).AddColumn("项目").AddColumn("值")
                            .AddRow("CVE", $"[teal]{Escape(c)}[/]")
                            .AddRow("名称", $"[white]{Escape(n)}[/]")
                            .AddRow("风险", $"[{riskColor}]{r}[/]")
                            .AddRow("CVSS", $"[yellow]{cvss}[/]")
                            .AddRow("描述", $"[grey]{Escape(desc.Length > 80 ? desc[..80] + "..." : desc)}[/]")
                            .AddRow("修复", $"[green]{Escape(fix.Length > 80 ? fix[..80] + "..." : fix)}[/]");
                        AnsiConsole.Write(tbl);
                        AnsiConsole.WriteLine();
                    }
                    return 0;
                }

            case "scan":
                AnsiConsole.MarkupLine("[yellow]Sirius 扫描通过引擎自动触发，使用 Web UI: http://localhost:3000[/]");
                return 0;

            case "status":
                {
                    var hosts = await client.GetHostsAsync();
                    if (hosts == null || hosts.Count == 0) { AnsiConsole.MarkupLine("[yellow]无扫描记录[/]"); return 0; }

                    AnsiConsole.Write(new Rule("[teal]Sirius 扫描历史[/]"));
                    var t = new Table().BorderColor(Color.Grey).AddColumn("主机ID").AddColumn("OS").AddColumn("首次发现").AddColumn("最近活跃");
                    foreach (var h in hosts.Take(10))
                        t.AddRow(h.Hid[..Math.Min(24, h.Hid.Length)], $"{Escape(h.Os ?? "?")}", h.FirstSeen ?? "?", h.LastSeen ?? "?");
                    AnsiConsole.Write(t);
                    return 0;
                }

            default:
                AnsiConsole.MarkupLine("[grey]用法: lmist sirius <summary|target <id>|status>[/]");
                return 1;
        }
    }

    private static string RiskLabelShort(string r) => r?.ToLower() switch { "critical" => "严重", "high" => "高危", "medium" => "中危", _ => "低危" };
    private static string RiskColor(string r) => r?.ToLower() switch { "critical" => "[red]严重[/]", "high" => "[yellow]高危[/]", "medium" => "[green]中危[/]", _ => "[grey]低危[/]" };
    private static string StatusColor(string s) => s?.ToLower() switch { "completed" or "done" => "[green]✅ 完成[/]", "running" => "[blue]▶ 运行中[/]", "failed" => "[red]❌ 失败[/]", _ => $"[grey]{s}[/]" };

    // ========================================
    // SIRIUS-SCAN (保留兼容)
    // ========================================
    private static async Task<int> SiriusScanCommand(string[] args)
    {
        if (args.Length == 0) { AnsiConsole.MarkupLine("[red]请指定目标 IP[/]"); return 1; }
        var target = args[0];
        var format = "html";
        var output = "sirius_report.html";
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--format" && i + 1 < args.Length) format = args[++i];
            else if (args[i] == "--output" && i + 1 < args.Length) output = args[++i];
        }
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;

        AnsiConsole.Write(new Rule($"[teal]Sirius Scan: {Escape(target)}[/]"));
        using var client = new SiriusClient();

        var (result, error) = await client.RunScanAsync(target, (msg, pct) =>
        {
            AnsiConsole.MarkupLine($"  [grey]{Escape(msg)}[/]");
        });

        if (result == null)
        {
            AnsiConsole.MarkupLine($"[red]Sirius 扫描失败: {Escape(error ?? "未知错误")}[/]");
            AnsiConsole.WriteLine();

            // Fallback to built-in
            AnsiConsole.MarkupLine("[yellow]回退到内置漏洞扫描...[/]");
            return await VulnScanCommand([target, "--authorized"]);
        }

        var report = SiriusClient.ConvertToReport(result);
        var gen = new ReportGenerator();
        var reportFormat = format.ToLower() switch
        {
            "json" => ReportGenerator.Format.Json,
            "csv" => ReportGenerator.Format.Csv,
            "md" or "markdown" => ReportGenerator.Format.Markdown,
            _ => ReportGenerator.Format.Html
        };
        var content = gen.Generate(report, reportFormat);
        await File.WriteAllTextAsync(output, content);

        AnsiConsole.MarkupLine($"[green]报告已生成: {Escape(output)}[/]");
        AnsiConsole.MarkupLine($"[grey]来源: Sirius Scan | 格式: {format} | 大小: {content.Length} 字符[/]");
        return 0;
    }

    private static async Task<int> ReportCommand(string[] args)
    {
        var format = "html";
        var output = "report.html";
        var target = "";

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--format" && i + 1 < args.Length) format = args[++i];
            else if (args[i].StartsWith("--format=")) format = args[i].Split('=', 2)[1];
            else if (args[i] == "--output" && i + 1 < args.Length) output = args[++i];
            else if (args[i].StartsWith("--output=")) output = args[i].Split('=', 2)[1];
            else if (args[i] == "--target" && i + 1 < args.Length) target = args[++i];
            else if (args[i].StartsWith("--target=")) target = args[i].Split('=', 2)[1];
        }

        if (string.IsNullOrWhiteSpace(target))
        {
            AnsiConsole.MarkupLine("[red]请指定 --target 参数[/]");
            AnsiConsole.MarkupLine("[grey]示例: lmist report --target 192.168.1.1 --format html[/]");
            return 1;
        }
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;

        var reportFormat = format.ToLower() switch
        {
            "json" => ReportGenerator.Format.Json,
            "md" or "markdown" => ReportGenerator.Format.Markdown,
            "csv" => ReportGenerator.Format.Csv,
            _ => ReportGenerator.Format.Html
        };

        var lf = LoggerFactory.Create(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));
        var sslTool = new SslCertificateTool(lf.CreateLogger<SslCertificateTool>());
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var report = new ReportGenerator.ScanReport
        {
            Target = target,
            GeneratedAt = DateTime.Now,
            ScanStatus = "running",
            StatusMessage = "正在执行目标发现、端口和漏洞检测",
            Scope = new ReportGenerator.ScanScope
            {
                Discovery = "ICMP 存活探测；ICMP 不可用时由工具尝试常见 TCP 端口回退",
                TcpPorts = "TCP 1-1000",
                VulnerabilityChecks = $"默认候选检测端口 {string.Join(',', VulnerabilityScanTool.DefaultScanPorts)}；外部数据源优先，内置 Banner 规则兜底",
                Limitations = "未扫描 UDP 和其余 TCP 端口；候选命中不能证明补丁状态或可利用性"
            }
        };

        // 1. Ping + 发现设备
        await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync("扫描中...", async _ =>
        {
            var pingTool = new PingScanTool(lf.CreateLogger<PingScanTool>());
            var pingResult = await pingTool.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "2000" });

            if (pingResult.Success)
            {
                try
                {
                    using var pd = JsonDocument.Parse(pingResult.Data);
                    var pr = pd.RootElement;
                    report.TotalDevices = pr.GetProperty("total").GetInt32();
                    report.OnlineDevices = pr.GetProperty("alive").GetInt32();

                    var devices = new List<string>();
                    if (pr.TryGetProperty("devices", out var devs))
                        foreach (var d in devs.EnumerateArray()) devices.Add(d.GetString()!);

                    if (devices.Count == 0)
                    {
                        report.ScanStatus = "no_targets";
                        report.StatusMessage = "未发现任何在线设备；未执行端口和漏洞扫描";
                        report.Warnings.Add("目标可能离线，也可能屏蔽了 ICMP 和回退探测；本报告不是安全结论");
                    }

                    // 2. 对在线设备做有界并行端口、TLS 和 OS 采集。
                    var deviceResults = await ReportDeviceCollector.CollectAsync(
                        devices,
                        (ip, ct) => ScanReportDeviceAsync(ip, lf, sslTool, ct),
                        GetReportConcurrency());
                    foreach (var deviceResult in deviceResults)
                    {
                        report.Devices.Add(deviceResult.Device);
                        report.OpenPorts.AddRange(deviceResult.OpenPorts);
                        report.SslInfo.AddRange(deviceResult.SslInfo);
                        report.Warnings.AddRange(deviceResult.Warnings);
                        report.Notes.AddRange(deviceResult.Notes);
                    }

                    // 3. 对所有在线设备做有界并行漏洞候选检测。
                    if (devices.Count > 0)
                    {
                        report.VulnInfo = await CollectVulnerabilityInfoAsync(report, devices);
                        ReportGenerator.ApplyCompletionStatus(report, devices.Count);
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Failed to build report data");
                    report.ScanStatus = "failed";
                    report.StatusMessage = $"报告数据构建失败：{ex.Message}";
                }
            }
            else
            {
                report.ScanStatus = "failed";
                report.StatusMessage = $"目标发现失败：{pingResult.Error ?? "未知错误"}";
                report.Warnings.Add("未执行端口、TLS 或漏洞扫描");
            }
        });

        sw.Stop();
        report.ScanDuration = $"{sw.Elapsed.TotalSeconds:F1}s";

        AnsiConsole.MarkupLine($"[grey]扫描状态 {Escape(report.ScanStatus)}: {report.OnlineDevices}/{report.TotalDevices} 设备, {report.OpenPorts.Count} 端口, {report.VulnInfo?.Findings.Count ?? 0} 漏洞, 耗时 {report.ScanDuration}[/]");

        if (report.VulnInfo != null && report.VulnInfo.Findings.Count > 0)
        {
            var v = report.VulnInfo;
            AnsiConsole.MarkupLine($"  [grey]风险: 严重 {v.CriticalCount} | 高危 {v.HighCount} | 中危 {v.MediumCount} | 低危 {v.LowCount}[/]");
        }

        var gen = new ReportGenerator();
        var content = gen.Generate(report, reportFormat);
        await File.WriteAllTextAsync(output, content);

        AnsiConsole.MarkupLine($"[green]报告已生成: {Escape(output)}[/]");
        AnsiConsole.MarkupLine($"[grey]格式: {format} | 大小: {content.Length} 字符[/]");
        return 0;
    }

    private static async Task CollectSslInfoAsync(
        ReportGenerator.ScanReport report,
        string target,
        SslCertificateTool sslTool,
        CancellationToken cancellationToken = default)
    {
        var tlsPorts = report.OpenPorts
            .Where(port => port.Target == target && PortHelper.IsLikelyTlsPort(port.Port))
            .Select(port => port.Port)
            .Distinct()
            .Order()
            .ToArray();

        foreach (var port in tlsPorts)
        {
            var result = await sslTool.ExecuteAsync(new ToolArguments
            {
                ["target"] = target,
                ["port"] = port.ToString(),
                ["timeout_ms"] = "3000"
            }, cancellationToken);
            if (!result.Success) continue;

            try
            {
                using var doc = JsonDocument.Parse(result.Data);
                var root = doc.RootElement;
                report.SslInfo.Add(new ReportGenerator.SslEntry
                {
                    Target = root.TryGetProperty("target", out var tlsTarget)
                        ? tlsTarget.GetString() ?? target
                        : target,
                    Port = root.TryGetProperty("port", out var tlsPort)
                        ? tlsPort.GetInt32()
                        : port,
                    Subject = root.TryGetProperty("subject", out var subject)
                        ? subject.GetString() ?? ""
                        : "",
                    Issuer = root.TryGetProperty("issuer", out var issuer)
                        ? issuer.GetString() ?? ""
                        : "",
                    NotAfter = root.TryGetProperty("notAfter", out var notAfter)
                        ? notAfter.GetString() ?? ""
                        : "",
                    DaysRemaining = root.TryGetProperty("daysRemaining", out var days)
                        ? days.GetInt32()
                        : 0,
                    IsExpired = root.TryGetProperty("isExpired", out var expired) && expired.GetBoolean(),
                    TrustErrors = root.TryGetProperty("trustErrors", out var trustErrors)
                        && trustErrors.ValueKind == JsonValueKind.Array
                            ? trustErrors.EnumerateArray()
                                .Select(error => error.GetString() ?? "")
                                .Where(error => error.Length > 0)
                                .ToList()
                            : new List<string>()
                });
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                Logger.LogWarning(ex, "Failed to parse TLS certificate result for report");
            }
        }
    }

    private static async Task<ReportDeviceScanResult> ScanReportDeviceAsync(
        string ip,
        ILoggerFactory loggerFactory,
        SslCertificateTool sslTool,
        CancellationToken cancellationToken)
    {
        var local = new ReportGenerator.ScanReport();
        var portTool = new PortScanTool(loggerFactory.CreateLogger<PortScanTool>());
        var portResult = await portTool.ExecuteAsync(new ToolArguments
        {
            ["target"] = ip,
            ["ports"] = "1-1000",
            ["timeout_ms"] = "2000"
        }, cancellationToken);
        if (portResult.Success)
        {
            try
            {
                using var ppd = JsonDocument.Parse(portResult.Data);
                if (ppd.RootElement.TryGetProperty("openPorts", out var openPorts))
                {
                    foreach (var item in openPorts.EnumerateArray())
                    {
                        var port = item.GetInt32();
                        local.OpenPorts.Add(new ReportGenerator.PortEntry
                        {
                            Target = ip,
                            Port = port,
                            Service = PortHelper.GetServiceName(port) ?? "?",
                            State = "open"
                        });
                    }
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                Logger.LogWarning(ex, "Failed to parse port scan result for report");
                local.Warnings.Add($"{ip}: 端口扫描结果无法解析");
            }
        }
        else
        {
            local.Warnings.Add($"{ip}: 端口扫描失败（{portResult.Error ?? "未知错误"}）");
        }

        await CollectSslInfoAsync(local, ip, sslTool, cancellationToken);

        var osGuess = "";
        try
        {
            var osTool = new OsFingerprintTool();
            var osResult = await osTool.ExecuteAsync(new ToolArguments
            {
                ["target"] = ip,
                ["timeout_ms"] = "2000"
            }, cancellationToken);
            if (osResult.Success)
            {
                using var osDocument = JsonDocument.Parse(osResult.Data);
                osGuess = osDocument.RootElement.GetProperty("osFamily").GetString() ?? "";
            }
            else
            {
                local.Notes.Add($"{ip}: OS 指纹未识别，不影响端口与漏洞候选结论");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Failed to detect OS fingerprint for report");
            local.Notes.Add($"{ip}: OS 指纹识别失败，不影响端口与漏洞候选结论");
        }

        return new ReportDeviceScanResult(
            new ReportGenerator.DeviceEntry { Ip = ip, IsAlive = true, OsGuess = osGuess },
            local.OpenPorts,
            local.SslInfo,
            local.Warnings,
            local.Notes);
    }

    private static int GetReportConcurrency() =>
        int.TryParse(Environment.GetEnvironmentVariable("LMIST_REPORT_CONCURRENCY"), out var configured)
            ? Math.Clamp(configured, 1, 8)
            : 4;

    private static async Task<ReportGenerator.VulnSummary?> CollectVulnerabilityInfoAsync(
        ReportGenerator.ScanReport report,
        IReadOnlyCollection<string> targets)
    {
        var results = new System.Collections.Concurrent.ConcurrentBag<(string Target, ToolResult Result)>();
        await Parallel.ForEachAsync(
            targets,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Min(3, Math.Max(1, targets.Count))
            },
            async (target, cancellationToken) =>
            {
                var tool = new VulnerabilityScanTool();
                var result = await tool.ExecuteAsync(new ToolArguments
                {
                    ["target"] = target,
                    ["timeout_ms"] = "5000"
                }, cancellationToken);
                results.Add((target, result));
            });

        var findings = new List<ReportGenerator.VulnFinding>();
        var successfulTargets = 0;
        foreach (var (target, result) in results.OrderBy(item => item.Target, StringComparer.OrdinalIgnoreCase))
        {
            if (!result.Success)
            {
                report.Warnings.Add($"{target}: 漏洞候选检测失败（{result.Error ?? "未知错误"}）");
                continue;
            }

            try
            {
                using var doc = JsonDocument.Parse(result.Data);
                var root = doc.RootElement;
                var resultTarget = root.TryGetProperty("target", out var scannedTarget)
                    ? scannedTarget.GetString() ?? target
                    : target;
                if (root.TryGetProperty("findings", out var items))
                {
                    findings.AddRange(items.EnumerateArray()
                        .Select(item => ReportGenerator.ParseVulnerabilityFinding(resultTarget, item)));
                }
                successfulTargets++;
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                Logger.LogWarning(ex, "Failed to parse vulnerability scan result for report target {Target}", target);
                report.Warnings.Add($"{target}: 漏洞扫描结果无法解析");
            }
        }

        return successfulTargets > 0
            ? ReportGenerator.BuildVulnerabilitySummary(findings)
            : null;
    }

    // ========================================
    // OS-FINGERPRINT
    // ========================================
    private static async Task<int> OsFingerprintCommand(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]请指定目标 IP[/]");
            return 1;
        }
        var target = args[0];
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;
        AnsiConsole.Write(new Rule($"[teal]OS 指纹识别: {Escape(target)}[/]"));
        var tool = new OsFingerprintTool();
        var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "5000" });

        if (!result.Success) { AnsiConsole.MarkupLine($"[red]{Escape(result.Error!)}[/]"); return 1; }

        try
        {
            using var doc = JsonDocument.Parse(result.Data);
            var r = doc.RootElement;
            var reachable = r.GetProperty("reachable").GetBoolean();
            var os = r.GetProperty("osFamily").GetString();
            var conf = r.GetProperty("confidence").GetInt32();
            var ttl = r.GetProperty("ttl").GetInt32();
            var pingMs = r.GetProperty("pingMs").GetInt64();
            var reasons = r.GetProperty("reasons").EnumerateArray().Select(x => x.GetString()).ToList();

            var table = new Table().BorderColor(Color.Grey)
                .AddColumn("项目").AddColumn("值")
                .AddRow("目标", Escape(target))
                .AddRow("可达", reachable ? "[green]是[/]" : "[red]否[/]")
                .AddRow("推断 OS", $"[teal]{Escape(os!)}[/]")
                .AddRow("置信度", conf > 50 ? $"[green]{conf}%[/]" : $"[yellow]{conf}%[/]")
                .AddRow("TTL", ttl > 0 ? $"{ttl}" : "—")
                .AddRow("延迟", pingMs > 0 ? $"{pingMs}ms" : "—");

            AnsiConsole.Write(table);

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[grey]推断依据:[/]");
            foreach (var reason in reasons!)
                AnsiConsole.MarkupLine($"  [grey]• {Escape(reason!)}[/]");

            AnsiConsole.MarkupLine($" [grey]耗时: {result.Duration.TotalSeconds:F1}s[/]");
        }
        catch { AnsiConsole.WriteLine(result.Data); }
        return 0;
    }

    // ========================================
    // VULN-SCAN
    // ========================================
    private static async Task<int> VulnScanCommand(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]请指定目标 IP[/]");
            return 1;
        }
        var target = args.FirstOrDefault(a => !a.StartsWith("-")) ?? "";
        if (string.IsNullOrWhiteSpace(target))
            return CliError("请指定目标 IP");
        if (!await ConfirmTargetAuthorizationAsync(target, args)) return 1;
        var showAll = args.Any(a => a == "--all");
        var useNmap = args.Any(a => a == "--use-nmap");

        AnsiConsole.Write(new Rule($"[teal]漏洞扫描: {Escape(target)}[/]"));

        // 第一步：端口扫描
        var lf = LoggerFactory.Create(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));
        var openPorts = new List<(int Port, string Service)>();

        await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync("端口扫描中...", async _ =>
        {
            var psTool = new PortScanTool(lf.CreateLogger<PortScanTool>());
            var psResult = await psTool.ExecuteAsync(new ToolArguments { ["target"] = target, ["ports"] = "1-1000", ["timeout_ms"] = "2000" });
            if (psResult.Success)
            {
                try
                {
                    using var pd = JsonDocument.Parse(psResult.Data);
                    if (pd.RootElement.TryGetProperty("openPorts", out var ops))
                    {
                        foreach (var p in ops.EnumerateArray())
                        {
                            var port = p.GetInt32();
                            openPorts.Add((port, PortHelper.GetServiceName(port) ?? "?"));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Failed to parse port scan result for vulnerability detail");
                }
            }
        });

        // OS 检测
        var cpeMatcher = new CpeMatcher(lf.CreateLogger<CpeMatcher>());
        var osGuess = await cpeMatcher.DetectOsAsync(target) ?? "未知";
        AnsiConsole.MarkupLine($"\n[grey]OS 识别: {Escape(osGuess)}[/]");

        // 显示端口扫描结果 + Banner
        var grabber = new BannerGrabber(useNmap, lf.CreateLogger<BannerGrabber>());
        if (openPorts.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[teal]📡 开放端口 + Banner:[/]");
            var pt = new Table().BorderColor(Color.Grey).AddColumn("端口").AddColumn("服务").AddColumn("版本").AddColumn("状态").AddColumn("CPE");
            foreach (var (port, svc) in openPorts)
            {
                var banner = await grabber.GrabAsync(target, port, 2000, osGuess);
                var ver = banner?.Version ?? "未识别";
                var isNmap = banner?.Source == "nmap";
                var isOsInherit = banner?.Source == "os-inherit";
                var verKnown = ver != "未识别" && !string.IsNullOrEmpty(ver);
                var cpe = cpeMatcher.Match(svc, verKnown ? ver : null, osGuess);
                var status = verKnown
                    ? (isNmap ? "[green]✅ nmap 识别[/]" : isOsInherit ? "[green]✅ OS 继承[/]" : "[green]✅ 已识别[/]")
                    : cpe != null ? "[yellow]⚠️ 服务级匹配[/]"
                    : "[red]❌ 无法识别[/]";
                var cpeDisplay = cpe != null
                    ? (cpe.IsVersionUnknown ? $"[yellow]{Escape(cpe.Cpe)}[/]" : $"[green]{Escape(cpe.Cpe)}[/]")
                    : "[grey]—[/]";
                var sourceTag = isNmap ? " [grey](nmap)[/]" : isOsInherit ? " [grey](OS继承)[/]" : "";
                var verDisplay = verKnown ? $"[green]{Escape(ver)}{sourceTag}[/]" : "[grey]未识别[/]";
                pt.AddRow($"[yellow]{port}[/]", $"[white]{svc}[/]",
                    verDisplay, status, cpeDisplay);
            }
            AnsiConsole.Write(pt);
        }
        else { AnsiConsole.MarkupLine("\n[yellow]未发现开放端口（1-1000）[/]"); }

        AnsiConsole.WriteLine();
        await AnsiConsole.Status().Spinner(Spinner.Known.Dots).StartAsync("漏洞检测中...", async _ =>
        {
            var tool = new VulnerabilityScanTool();
            var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = target, ["timeout_ms"] = "5000" });

            if (!result.Success) { AnsiConsole.MarkupLine($"[red]{Escape(result.Error!)}[/]"); return; }

            try
            {
                using var doc = JsonDocument.Parse(result.Data);
                var r = doc.RootElement;
                var critical = r.TryGetProperty("criticalCount", out var cc) ? cc.GetInt32() : 0;
                var high = r.GetProperty("highCount").GetInt32();
                var med = r.GetProperty("mediumCount").GetInt32();
                var low = r.GetProperty("lowCount").GetInt32();
                var total = r.GetProperty("totalFindings").GetInt32();

                AnsiConsole.WriteLine();

                if (total == 0)
                {
                    AnsiConsole.MarkupLine("[green]✅ 未发现漏洞风险[/]");
                    return;
                }

                // 紧急摘要
                var panel = new Panel("")
                    .Header("[yellow] 📊 紧急摘要 [/]")
                    .BorderColor(Color.Yellow);
                var summaryLines = new List<string>();
                if (critical > 0) summaryLines.Add($"[red]🔴 {critical} 个严重漏洞需要立即处理[/]");
                if (high > 0) summaryLines.Add($"[yellow]🟡 {high} 个高危漏洞建议尽快修复[/]");
                if (critical + high > 0) summaryLines.Add($"[grey]💡 建议优先修复 {(critical > 0 ? "严重" : "高危")}级别漏洞[/]");
                if (summaryLines.Count == 0) summaryLines.Add("[green]无紧急漏洞[/]");
                panel = new Panel(string.Join("\n", summaryLines))
                    .Header("[yellow] 📊 紧急摘要 [/]")
                    .BorderColor(Color.Yellow);
                AnsiConsole.Write(panel);
                AnsiConsole.WriteLine();

                // 收集并分组
                if (!r.TryGetProperty("findings", out var findings) || findings.GetArrayLength() == 0) return;

                var items = findings.EnumerateArray()
                    .Select(f => (
                        port: f.GetProperty("port").GetInt32(),
                        svc: f.GetProperty("service").GetString() ?? "?",
                        cve: f.TryGetProperty("cve", out var cv) ? cv.GetString() : null,
                        risk: f.TryGetProperty("risk", out var rk) ? rk.GetString() ?? "low" : "low",
                        cvss: f.TryGetProperty("cvss", out var cs) && cs.TryGetDouble(out var sc) ? sc : double.NaN,
                        source: f.TryGetProperty("source", out var sr) ? sr.GetString() ?? "—" : "—",
                        confirmed: f.TryGetProperty("confirmed", out var cf) && cf.GetBoolean(),
                        versionStatus: ReadVersionStatus(f),
                        fix: f.TryGetProperty("fix", out var fx) ? fx.GetString() : null,
                        name: f.TryGetProperty("name", out var nm) ? nm.GetString() : null
                    ))
                    .OrderByDescending(x => x.risk switch { "critical" => 4, "high" => 3, "medium" => 2, _ => 1 })
                    .ThenByDescending(x => double.IsNaN(x.cvss) ? 0 : x.cvss)
                    .ToList();

                var displayItems = showAll ? items : items.Take(10).ToList();
                var riskGroups = displayItems.GroupBy(x => x.risk).OrderByDescending(g => g.Key switch { "critical" => 4, "high" => 3, "medium" => 2, _ => 1 });

                // 按风险分组显示
                foreach (var group in riskGroups)
                {
                    var (emoji, color) = group.Key switch
                    {
                        "critical" => ("🔴", "red"),
                        "high" => ("🟡", "yellow"),
                        "medium" => ("🟢", "green"),
                        _ => ("⚪", "grey")
                    };
                    AnsiConsole.MarkupLine($"[{color}]{emoji} {RiskLabel(group.Key)} ({group.Count()})[/]");

                    foreach (var item in group)
                    {
                        var cvssStr = double.IsNaN(item.cvss) ? "[grey]N/A[/]" : $"[yellow]{item.cvss:F1}[/]";
                        var cveDisplay = item.cve ?? "—";
                        var desc = item.name ?? "";
                        if (desc.Length > 50) desc = desc[..50] + "...";
                        var confidence = VulnerabilityConfidenceLabel(
                            item.confirmed,
                            item.versionStatus);
                        var confTag = item.confirmed
                            ? $"[green]{confidence}[/]"
                            : $"[yellow]{confidence}[/]";
                        AnsiConsole.MarkupLine($"  [grey]├─[/] [teal]{Escape(cveDisplay)}[/] {cvssStr} {confTag} [grey]— {Escape(desc)}[/]");
                    }
                    AnsiConsole.WriteLine();
                }

                if (!showAll && items.Count > 10)
                    AnsiConsole.MarkupLine($"[grey]... 还有 {items.Count - 10} 个漏洞。使用 --all 查看全部[/]");

                // 修复建议（去重，过滤通用提示，按风险排序，优先内置库的具体建议）
                var uniqueFixes = items
                    .Where(x => x.fix != null &&
                           !x.fix!.StartsWith("参考 NVD") &&
                           !x.fix!.StartsWith("参考官方") &&
                           x.fix != "参考官方公告" &&
                           x.fix != "升级到最新版本")
                    .GroupBy(x => x.fix!)
                    .Select(g => g.First())
                    .OrderByDescending(x => x.risk switch { "critical" => 4, "high" => 3, "medium" => 2, _ => 1 })
                    .Take(5)
                    .ToList();

                // 如果全是通用提示，给端口级别的建议
                if (uniqueFixes.Count == 0)
                {
                    var openPorts = items.Select(x => x.port).Distinct().ToList();
                    var portAdvice = new Dictionary<int, string>
                    {
                        [445] = "安装 MS17-010/KB4551762 对应更新，禁用 SMBv1；SMBGhost 临时缓解应禁用 SMB 压缩，并限制 445 访问",
                        [3389] = "安装 KB4499181，或禁用远程桌面（除非必要）",
                        [135] = "禁用 RPC 端点映射器（如非必要），使用防火墙限制访问",
                        [22] = "升级 OpenSSH 到最新版本，禁用密码登录改用密钥",
                        [3306] = "升级 MySQL，禁用远程 root 登录",
                        [6379] = "升级 Redis，启用 AUTH 密码认证",
                        [80] = "升级 HTTP 服务器，启用 HTTPS 重定向",
                    };
                    foreach (var p in openPorts.Take(3))
                        if (portAdvice.TryGetValue(p, out var advice))
                            uniqueFixes.Add((p, "?", $"端口 {p}", "low", double.NaN, "内置库", false, "unknown", advice, (string?)null));
                }

                if (uniqueFixes.Count > 0)
                {
                    AnsiConsole.WriteLine();
                    AnsiConsole.MarkupLine("[teal]📋 修复建议:[/]");
                    foreach (var item in uniqueFixes)
                        AnsiConsole.MarkupLine($"  [yellow]{Escape(item.cve switch { "?" => $"端口 {item.port}", _ => item.cve ?? "—" })}[/] [grey]({RiskLabel(item.risk)}): {Escape(item.fix!)}[/]");
                }

                // 扫描总结
                var sources = items.Select(x => x.source).Where(s => s != "内置库").Distinct().ToList();
                var sourceStr = sources.Count > 0 ? string.Join(" + ", sources) : "内置库";

                AnsiConsole.WriteLine();
                var sumTable = new Table().BorderColor(Color.Grey).HideHeaders()
                    .AddColumn("K").AddColumn("V")
                    .AddRow("[grey]目标[/]", $"[white]{Escape(target)}[/]")
                    .AddRow("[grey]漏洞总数[/]", $"[white]{total}[/]")
                    .AddRow("[grey]风险分布[/]", $"[red]严重 {critical}[/] | [yellow]高危 {high}[/] | [green]中危 {med}[/] | [grey]低危 {low}[/]")
                    .AddRow("[grey]数据来源[/]", $"[teal]{Escape(sourceStr)}[/]");
                AnsiConsole.Write(new Panel(sumTable)
                    .Header("[teal] 📊 扫描总结 [/]")
                    .BorderColor(Color.Teal));

                AnsiConsole.MarkupLine($" [grey]耗时: {result.Duration.TotalSeconds:F1}s[/]");
            }
            catch { AnsiConsole.WriteLine(result.Data); }
        });
        return 0;
    }

    // ========================================
    // VULN-DETAIL
    // ========================================
    private static async Task<int> VulnDetailCommand(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]请指定 CVE 编号[/]");
            AnsiConsole.MarkupLine("[grey]示例: lmist vuln-detail CVE-2017-0144[/]");
            return 1;
        }
        var cveId = args[0].ToUpper();

        AnsiConsole.Write(new Rule($"[teal]CVE 详情: {Escape(cveId)}[/]"));

        // 1. 查内置库
        var builtIn = CveDatabase.FindByCve(cveId);
        if (builtIn != null)
        {
            var riskEmoji = builtIn.Risk switch { "critical" => "🔴", "high" => "🟡", "medium" => "🟢", _ => "⚪" };
            var table = new Table().BorderColor(Color.Grey)
                .AddColumn("项目").AddColumn("值")
                .AddRow("CVE", $"[teal]{builtIn.Cve}[/]")
                .AddRow("名称", $"[white]{Escape(builtIn.Name)}[/]")
                .AddRow("端口", $"[yellow]{builtIn.Port}[/]")
                .AddRow("服务", $"[white]{builtIn.Service}[/]")
                .AddRow("风险", $"{riskEmoji} {RiskLabel(builtIn.Risk)}")
                .AddRow("检测方式", $"[grey]{builtIn.DetectProbe}[/]")
                .AddRow("修复建议", $"[green]{Escape(builtIn.Fix)}[/]");
            AnsiConsole.Write(table);
        }

        // 2. 查 Shodan API
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var resp = await http.GetAsync($"https://cvedb.shodan.io/cve/{cveId}");
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync();
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var r = doc.RootElement;

                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[teal]📡 Shodan API 数据:[/]");

                var summary = r.TryGetProperty("summary", out var s) ? s.GetString() :
                              r.TryGetProperty("description", out var d) ? d.GetString() : null;
                if (summary != null)
                    AnsiConsole.MarkupLine($"  [grey]描述: {Escape(summary)}[/]");

                if (r.TryGetProperty("cvss_v3", out var cv3) && cv3.TryGetDouble(out var v3))
                    AnsiConsole.MarkupLine($"  [yellow]CVSS v3: {v3:F1}[/]");
                else if (r.TryGetProperty("cvss", out var cv) && cv.TryGetDouble(out var v))
                    AnsiConsole.MarkupLine($"  [yellow]CVSS: {v:F1}[/]");

                if (r.TryGetProperty("references", out var refs))
                {
                    AnsiConsole.MarkupLine("  [grey]参考链接:[/]");
                    foreach (var rf in refs.EnumerateArray().Take(3))
                        AnsiConsole.MarkupLine($"    [blue]{Escape(rf.GetString() ?? "")}[/]");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "NVD API unreachable");
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[grey]NVD 参考: https://nvd.nist.gov/vuln/detail/{cveId}[/]");
        return 0;
    }

    private static string RiskLabel(string risk) => risk switch
    {
        "critical" => "严重漏洞",
        "high" => "高危漏洞",
        "medium" => "中危漏洞",
        _ => "低危漏洞"
    };

    private static async Task<bool> ConfirmTargetAuthorizationAsync(
        string target,
        IReadOnlyCollection<string> args)
    {
        var validation = await TargetGuard.ValidateAsync(target);
        if (!validation.IsAllowed)
        {
            AnsiConsole.MarkupLine(
                $"[red]目标被拒绝 ({Escape(validation.Code)}): {Escape(validation.Message)}[/]");
            return false;
        }

        if (!validation.RequiresPublicAuthorization)
            return true;

        if (args.Contains("--authorized", StringComparer.OrdinalIgnoreCase))
        {
            AnsiConsole.MarkupLine("[yellow]已通过 --authorized 确认拥有公网目标扫描授权。[/]");
            return true;
        }

        if (Console.IsInputRedirected)
        {
            AnsiConsole.MarkupLine(
                "[red]公网目标需要授权确认；非交互运行请在确认有权扫描后添加 --authorized。[/]");
            return false;
        }

        return AnsiConsole.Confirm(
            $"目标 {Escape(target)} 位于公网。你确认拥有扫描该目标的授权吗？",
            defaultValue: false);
    }

    internal static string VulnerabilityConfidenceLabel(
        bool confirmed,
        string? versionStatus)
    {
        if (confirmed) return "✔已验证";

        return versionStatus?.Trim().ToLowerInvariant() switch
        {
            "verified" => "⚠候选（版本已验证）",
            "unverified" => "⚠候选（版本未验证）",
            _ => "⚠候选（版本未知）"
        };
    }

    private static string ReadVersionStatus(JsonElement finding)
    {
        if (finding.TryGetProperty("versionStatus", out var status)
            && status.ValueKind == JsonValueKind.String)
        {
            return status.GetString() ?? "unknown";
        }

        return finding.TryGetProperty("versionVerified", out var verified)
            && verified.ValueKind is JsonValueKind.True or JsonValueKind.False
            && verified.GetBoolean()
                ? "verified"
                : "unknown";
    }

    // AGENT — 使用配置文件中的模型
    // ========================================
    private async Task<int> AgentCommand(
        string[] args,
        Action<string>? sessionStarted = null,
        bool renderResumeHistory = true,
        CancellationToken ct = default)
    {
        var store = new AgentSessionStore(
            Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db"));

        if (args.Length == 0)
            return await RunInteractiveAgentAsync(store);

        if (args.Length == 1 && args[0] == "--list")
            return await ListAgentSessionsAsync(store);

        string? resumeSessionId = null;
        var message = string.Join(' ', args);
        var userMessage = message;

        if (args[0] == "--resume")
        {
            if (args.Length < 2)
            {
                AnsiConsole.MarkupLine("[red]请提供会话 ID: lmist agent --resume {id}[/]");
                return 1;
            }

            resumeSessionId = args[1];
            var resume = await store.GetSessionAsync(resumeSessionId);
            if (resume == null)
            {
                AnsiConsole.MarkupLine($"[red]会话不存在: {Escape(resumeSessionId)}[/]");
                return 1;
            }

            var history = await store.GetMessagesAsync(resumeSessionId);
            if (renderResumeHistory)
                RenderSessionHistory(resume, history);

            if (args.Length < 3)
            {
                AnsiConsole.MarkupLine("[grey]继续对话: lmist agent --resume {id} \"新消息\"[/]");
                return 0;
            }

            userMessage = string.Join(' ', args[2..]);
            message = BuildHistoryContext(history) + userMessage;
        }

        // 默认不泄露本机拓扑；仅显式开启时注入。
        if (Environment.GetEnvironmentVariable("LMIST_INJECT_NETWORK_INFO") == "true")
        {
            var entries = LocalNetworkInfo.GetEntries();
            if (entries.Count > 0)
            {
                var ipInfo = string.Join("; ", entries.Select(e =>
                    $"{e.Ip}/{e.Prefix} (接口: {e.Name}, 网关: {e.Gateway})"));
                message = $"[本机网络信息: {ipInfo}] {message}";
            }
        }

        var promptPath = FindFile("config/prompts/system_prompt.txt");
        var systemPrompt = File.Exists(promptPath)
            ? await File.ReadAllTextAsync(promptPath)
            : "你是助手。输出 JSON: {thought, action, action_input}";

        var (provider, model, endpoint, apiKey) = ReadLLMConfig();

        var session = resumeSessionId != null
            ? await store.GetSessionAsync(resumeSessionId)
            : await store.CreateSessionAsync("Agent 会话", model);
        session ??= await store.CreateSessionAsync("Agent 会话", model);
        sessionStarted?.Invoke(session.Id);
        await store.AddMessageAsync(session.Id, "user", userMessage);

        // 头部面板
        AnsiConsole.Write(new Panel(
            $"[white]{Escape(message)}[/]")
            .Header("[teal] LucentMist Agent [/]")
            .BorderColor(Color.Teal));

        var providerName = provider == "claude"
            ? "Claude API"
            : provider == "deepseek"
                ? $"DeepSeek API @ {endpoint}"
                : $"Ollama @ {endpoint}";
        var info = new Table()
            .AddColumn(new TableColumn("项目").RightAligned())
            .AddColumn("值")
            .HideHeaders()
            .BorderColor(Color.Grey)
            .AddRow("[grey]Provider[/]", $"[blue]{provider}[/]")
            .AddRow("[grey]模型[/]", $"[green]{model}[/]")
            .AddRow("[grey]地址[/]", $"[white]{providerName}[/]")
            .AddRow("[grey]工具[/]", "[blue]ping_scan[/] / [blue]port_scan[/] / [blue]service_identify[/] / [blue]os_fingerprint[/] / [blue]ssl_check[/] / [blue]udp_scan[/] / [blue]vuln_scan[/] / [blue]sirius_scan[/]");
        AnsiConsole.Write(info);
        AnsiConsole.WriteLine();

        var lf = LoggerFactory.Create(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning));

        ILLMProvider llm = provider == "claude"
            ? new ClaudeProvider(apiKey, model, lf.CreateLogger<ClaudeProvider>())
            : provider == "deepseek"
                ? new OpenAIProvider(apiKey, model, endpoint, lf.CreateLogger<OpenAIProvider>())
                : new OllamaProvider(endpoint, model, lf.CreateLogger<OllamaProvider>());

        var toolRegistry = ToolRegistryFactory.CreateDefault(lf);

        var engine = new ReActEngine(
            llm,
            toolRegistry,
            systemPrompt,
            lf.CreateLogger<ReActEngine>(),
            new SqliteNetworkAuditSink(CreateScanStore(), "cli-agent"),
            "cli-agent")
        { MaxRounds = 5 };

        try
        {
            ReActResult? result = null;
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("teal"))
                .StartAsync("AI 分析中...", async _ =>
                {
                    result = await engine.RunAsync(message, ct);
                });

            if (result == null) return 1;

            // 推理过程
            if (engine.ThoughtLog.Count > 0)
            {
                AnsiConsole.Write(new Rule("[grey]推理过程[/]"));
                for (int i = 0; i < engine.ThoughtLog.Count; i++)
                {
                    await store.AddMessageAsync(session.Id, "assistant", engine.ThoughtLog[i]);
                    AnsiConsole.MarkupLine($"  [yellow] {i + 1}.[/] [white]{Escape(engine.ThoughtLog[i])}[/]");
                    foreach (var obs in engine.ObservationsForRound(i + 1))
                    {
                        await store.AddMessageAsync(
                            session.Id,
                            "tool",
                            obs.Result,
                            System.Text.Json.JsonSerializer.Serialize(new
                            {
                                tool = obs.ToolName,
                                input = obs.Input,
                                success = obs.Success,
                            }));
                        AnsiConsole.MarkupLine($"     [blue]-> {obs.ToolName}[/]");
                        RenderObservation(obs.ToolName, obs.Result);
                    }
                }
            }

            // 结论
            AnsiConsole.WriteLine();
            await store.AddMessageAsync(session.Id, "assistant", result.Answer);
            await store.UpdateTitleAsync(session.Id, TitleFrom(userMessage));
            var panel = new Panel(Markup.Escape(result.Answer))
                .Header(" 分析结论 ")
                .BorderColor(Color.Green);
            AnsiConsole.Write(panel);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (TaskCanceledException)
        {
            await store.AddMessageAsync(session.Id, "assistant", "超时: LLM 响应超时");
            AnsiConsole.MarkupLine("[red]超时: LLM 响应超时[/]");
            AnsiConsole.MarkupLine("[grey]建议: 首次加载模型较慢，请重试[/]");
            return 1;
        }
        catch (HttpRequestException ex)
        {
            await store.AddMessageAsync(session.Id, "assistant", $"网络错误: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]网络错误: {Escape(ex.Message)}[/]");
            AnsiConsole.MarkupLine("[grey]请确认 Ollama / API 服务正在运行[/]");
            return 1;
        }
        catch (Exception ex)
        {
            await store.AddMessageAsync(session.Id, "assistant", $"错误: {ex.Message}");
            AnsiConsole.MarkupLine($"[red]错误: {Escape(ex.Message)}[/]");
            return 1;
        }

        return 0;
    }

    private async Task<int> RunInteractiveAgentAsync(AgentSessionStore store)
    {
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;
        try
        {
            return await RunAgentReplLoopAsync(
                Console.In,
                Console.Out,
                async (input, sessionId, token) =>
                {
                    string? resultingSessionId = sessionId;
                    var turnArgs = sessionId == null
                        ? new[] { input }
                        : new[] { "--resume", sessionId, input };
                    var exitCode = await AgentCommand(
                        turnArgs,
                        id => resultingSessionId = id,
                        renderResumeHistory: false,
                        token);
                    return new AgentReplTurnResult(exitCode, resultingSessionId);
                },
                cts.Token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            Console.WriteLine();
            AnsiConsole.MarkupLine("[grey]Agent 交互已退出[/]");
            return 0;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    internal static async Task<int> RunAgentReplLoopAsync(
        TextReader input,
        TextWriter output,
        Func<string, string?, CancellationToken, Task<AgentReplTurnResult>> runTurn,
        CancellationToken ct = default)
    {
        await output.WriteLineAsync("LucentMist Agent 交互模式。输入 exit 或 quit 退出。");
        string? sessionId = null;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            await output.WriteAsync("agent> ");
            await output.FlushAsync(ct);
            var line = await input.ReadLineAsync(ct);
            if (line == null || line.Trim() is "exit" or "quit")
                return 0;
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var turn = await runTurn(line.Trim(), sessionId, ct);
            if (!string.IsNullOrWhiteSpace(turn.SessionId))
                sessionId = turn.SessionId;
        }
    }

    internal sealed record AgentReplTurnResult(int ExitCode, string? SessionId);

    private static async Task<int> ListAgentSessionsAsync(AgentSessionStore store)
    {
        var sessions = await store.ListSessionsAsync(1, 50);
        if (sessions.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]暂无 Agent 会话[/]");
            return 0;
        }

        var table = new Table()
            .AddColumn("ID")
            .AddColumn("标题")
            .AddColumn("模型")
            .AddColumn("消息数")
            .AddColumn("更新时间")
            .BorderColor(Color.Grey);

        foreach (var s in sessions)
        {
            table.AddRow(
                s.Id[..8],
                Escape(s.Title),
                s.Model,
                s.MessageCount.ToString(),
                s.UpdatedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        }

        AnsiConsole.Write(table);
        return 0;
    }

    private static void RenderSessionHistory(
        AgentSessionRecord session, List<AgentMessageRecord> messages)
    {
        AnsiConsole.Write(new Rule($"[grey]{Escape(session.Title)} ({session.MessageCount} 条)[/]"));
        foreach (var m in messages)
        {
            var role = m.Role switch
            {
                "user" => "用户",
                "assistant" => "助手",
                "tool" => "工具",
                _ => m.Role,
            };
            var content = m.Content.Length > 200 ? m.Content[..200] + "..." : m.Content;
            AnsiConsole.MarkupLine($"  [teal]{role}:[/] {Escape(content)}");
        }
    }

    private static string BuildHistoryContext(List<AgentMessageRecord> messages)
    {
        if (messages.Count == 0) return "";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("以下是之前会话的历史记录，请基于此继续回答：");
        foreach (var m in messages)
            sb.AppendLine($"{m.Role}: {m.Content}");
        sb.AppendLine();
        return sb.ToString();
    }

    private static string TitleFrom(string message)
    {
        var text = message.Trim();
        return text.Length <= 20 ? text : text[..20] + "...";
    }

    // ========================================
    // RENDER HELPERS
    // ========================================
    private static void RenderPingResult(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var total = r.GetProperty("total").GetInt32();
            var alive = r.GetProperty("alive").GetInt32();

            var table = new Table()
                .AddColumn("项目")
                .AddColumn("数值")
                .AddRow("扫描 IP 数", $"{total}")
                .AddRow("在线设备数", $"[green]{alive}[/]")
                .BorderColor(Color.Grey);
            AnsiConsole.Write(table);

            if (r.TryGetProperty("devices", out var devs))
            {
                var devices = devs.EnumerateArray().Select(d => d.GetString()).ToList();
                if (devices.Count > 0)
                {
                    AnsiConsole.WriteLine();
                    foreach (var d in devices!)
                        AnsiConsole.MarkupLine($"  [green]  {Escape(d!)}[/]");
                }
            }

            if (r.TryGetProperty("hint", out var hint) && hint.ValueKind == JsonValueKind.String)
                AnsiConsole.MarkupLine($"  [yellow]{Escape(hint.GetString() ?? "")}[/]");
        }
        catch { AnsiConsole.WriteLine(json); }
    }

    private static void RenderObservation(string toolName, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;

            switch (toolName)
            {
                case "ping_scan":
                    RenderPingObs(r);
                    break;
                case "port_scan":
                    RenderPortObs(r);
                    break;
                case "service_identify":
                    RenderServiceObs(r);
                    break;
                default:
                    AnsiConsole.MarkupLine($"     [grey]{Escape(json)}[/]");
                    break;
            }
        }
        catch
        {
            var shortText = json.Length > 200 ? json[..200] + "..." : json;
            AnsiConsole.MarkupLine($"     [grey]{Escape(shortText)}[/]");
        }
    }

    private static void RenderPingObs(JsonElement r)
    {
        var alive = r.GetProperty("alive").GetInt32();
        var total = r.GetProperty("total").GetInt32();
        AnsiConsole.MarkupLine($"      [grey]扫描 {total} 个 IP[/]  [green]发现 {alive} 台在线[/]");

        if (r.TryGetProperty("devices", out var devs))
        {
            foreach (var d in devs.EnumerateArray())
                AnsiConsole.MarkupLine($"        [green]{Escape(d.GetString() ?? "-")}[/]");
        }

        if (r.TryGetProperty("hint", out var hint) && hint.ValueKind == JsonValueKind.String)
            AnsiConsole.MarkupLine($"        [yellow]{Escape(hint.GetString() ?? "")}[/]");
    }

    private static void RenderPortObs(JsonElement r)
    {
        var target = r.GetProperty("target").GetString() ?? "?";
        var scanned = r.GetProperty("totalScanned").GetInt32();
        var ports = r.TryGetProperty("openPorts", out var p)
            ? p.EnumerateArray().Select(x => x.GetInt32()).ToList()
            : new List<int>();

        var wellKnown = PortHelper.TcpServices;

        var summary = new Table()
            .AddColumn("项目")
            .AddColumn("数值")
            .AddRow("目标", Escape(target))
            .AddRow("扫描端口", $"{scanned}")
            .AddRow("开放端口", $"[green]{ports.Count}[/]")
            .BorderColor(Color.Grey);
        AnsiConsole.Write(summary);

        if (ports.Count > 0)
        {
            var portTable = new Table()
                .AddColumn("端口")
                .AddColumn("服务")
                .BorderColor(Color.Grey);

            foreach (var port in ports)
            {
                var name = wellKnown.GetValueOrDefault(port, "未知");
                portTable.AddRow(
                    $"[yellow]{port}[/]",
                    $"[green]{name}[/]");
            }
            AnsiConsole.Write(portTable);
        }
    }

    private static void RenderServiceObs(JsonElement r)
    {
        var target = r.GetProperty("target").GetString() ?? "?";
        var port = r.GetProperty("port").GetInt32();
        var service = r.GetProperty("serviceName").GetString() ?? "?";

        AnsiConsole.MarkupLine($"     [grey]目标  {Escape(target)}:{port}[/]");
        AnsiConsole.MarkupLine($"     [green]服务  {Escape(service)}[/]");
    }

    private static string Escape(string text) =>
        Markup.Escape(text).Replace("[", "[[").Replace("]", "]]");

    private static int CliError(string message)
    {
        AnsiConsole.MarkupLine($"[red]{Escape(message)}[/]");
        return 1;
    }

    private static string FindFile(string relativePath)
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", relativePath),
            relativePath,
            Path.Combine("..", "..", "..", relativePath),
        };
        return candidates.FirstOrDefault(File.Exists) ?? relativePath;
    }

    // ========================================
    // CONFIG — 支持查看和切换
    // ========================================
    private static async Task<int> ConfigCommand(string[] args)
    {
        // 处理 --set 参数
        if (args.Length >= 2 && args[0].ToLower() == "--set")
        {
            var parts = string.Join(" ", args[1..]).Split('=', 2);
            if (parts.Length == 2)
            {
                var key = parts[0].Trim();
                var value = parts[1].Trim();
                WriteLLMConfig(
                    key == "Provider" ? value : null,
                    key == "Model" ? value : null);

                AnsiConsole.MarkupLine($"[green]已更新: {key} = {value}[/]");
                AnsiConsole.MarkupLine("[grey]配置已写入 config/appsettings.json[/]");
            }
            else
            {
                AnsiConsole.MarkupLine("[red]格式错误，示例: --set Model=qwen2.5:7b[/]");
            }
            return 0;
        }

        // 显示当前配置
        var (provider, model, endpoint, apiKey) = ReadLLMConfig();

        var table = new Table()
            .BorderColor(Color.Grey)
            .AddColumn("配置项")
            .AddColumn("当前值")
            .AddColumn("可选项");

        table.AddRow("[grey]Provider[/]", $"[blue]{provider}[/]", "[grey]ollama | claude | deepseek[/]");
        table.AddRow("[grey]Model[/]", $"[green]{model}[/]", "[grey]qwen2.5:7b | llama3.1:8b | deepseek-chat[/]");

        if (provider == "ollama")
            table.AddRow("[grey]Endpoint[/]", $"[white]{endpoint}[/]", "[grey]http://localhost:11434[/]");
        else
            table.AddRow("[grey]API Key[/]", apiKey.Length > 5 ? "[green]已配置[/]" : "[yellow]未配置[/]", "[grey]sk-ant-... / sk-...[/]");

        AnsiConsole.Write(new Panel(table)
            .Header("[teal] LLM 配置 [/]")
            .BorderColor(Color.Teal));

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[grey]切换示例:[/]");
        AnsiConsole.MarkupLine("  [yellow]lmist config --set Model=qwen2.5:7b[/]");
        AnsiConsole.MarkupLine("  [yellow]lmist config --set Provider=claude[/]");
        AnsiConsole.MarkupLine("  [yellow]lmist config --set Provider=deepseek[/]");

        return await Task.FromResult(0);
    }

    // ========================================
    // AUDIT
    // ========================================
    private static async Task<int> AuditCommand(string[] args)
    {
        var limit = 50;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--limit" && i + 1 < args.Length)
            {
                if (!int.TryParse(args[++i], out limit) || limit is < 1 or > 1000)
                    return CliError("--limit 必须是 1-1000 的整数");
            }
            else if (args[i].StartsWith("--limit=", StringComparison.Ordinal)
                && (!int.TryParse(args[i].Split('=', 2)[1], out limit) || limit is < 1 or > 1000))
            {
                return CliError("--limit 必须是 1-1000 的整数");
            }
        }

        var records = await CreateScanStore().ListAuditAsync(limit);
        var table = new Table()
            .BorderColor(Color.Grey)
            .AddColumn("UTC 时间")
            .AddColumn("发起者")
            .AddColumn("目标")
            .AddColumn("类型")
            .AddColumn("状态")
            .AddColumn("摘要");
        foreach (var record in records)
        {
            table.AddRow(
                record.OccurredAt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                Escape(record.Initiator),
                Escape(record.Target),
                Escape(record.ScanType),
                Escape(record.Status),
                Escape(record.Summary));
        }

        AnsiConsole.Write(new Rule("[teal]扫描审计记录[/]"));
        AnsiConsole.Write(table);
        if (records.Count == 0)
            AnsiConsole.MarkupLine("[grey]暂无扫描审计记录[/]");
        return 0;
    }

    private static int BackupCommand(string[] args)
    {
        var database = Environment.GetEnvironmentVariable("LMIST_DB")
            ?? Path.Combine("data", "lucentmist.db");
        var output = Path.Combine(
            "backups",
            $"lucentmist-{DateTime.UtcNow:yyyyMMddHHmmss}.db");
        var overwrite = args.Contains("--force", StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--output" && i + 1 < args.Length) output = args[++i];
            else if (args[i].StartsWith("--output=", StringComparison.Ordinal))
                output = args[i].Split('=', 2)[1];
            else if (args[i] == "--database" && i + 1 < args.Length) database = args[++i];
            else if (args[i].StartsWith("--database=", StringComparison.Ordinal))
                database = args[i].Split('=', 2)[1];
        }

        try
        {
            var path = DatabaseBackupService.Backup(database, output, overwrite);
            AnsiConsole.MarkupLine($"[green]备份完成：{Escape(path)}[/]");
            AnsiConsole.MarkupLine("[grey]已执行 WAL checkpoint、SQLite 在线备份与完整性检查。[/]");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or SqliteException or InvalidOperationException)
        {
            return CliError($"备份失败：{ex.Message}");
        }
    }

    private static int RestoreCommand(string[] args)
    {
        var backup = args.FirstOrDefault(argument => !argument.StartsWith('-')) ?? "";
        var database = Environment.GetEnvironmentVariable("LMIST_DB")
            ?? Path.Combine("data", "lucentmist.db");
        var confirmed = args.Contains("--yes", StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--database" && i + 1 < args.Length) database = args[++i];
            else if (args[i].StartsWith("--database=", StringComparison.Ordinal))
                database = args[i].Split('=', 2)[1];
        }

        if (string.IsNullOrWhiteSpace(backup))
            return CliError("请指定备份文件：lmist restore <backup.db> --yes");
        if (!confirmed)
            return CliError("恢复会替换当前数据库；停止 API/Web 后添加 --yes 再执行");

        try
        {
            var result = DatabaseBackupService.Restore(backup, database);
            AnsiConsole.MarkupLine($"[green]恢复完成：{Escape(result.DatabasePath)}[/]");
            if (result.SafetyCopyDirectory != null)
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]旧数据库及 WAL/SHM 已移至：{Escape(result.SafetyCopyDirectory)}[/]");
            }
            return 0;
        }
        catch (Exception ex) when (ex is IOException or SqliteException or InvalidOperationException)
        {
            return CliError($"恢复失败：{ex.Message}");
        }
    }

    // ========================================
    // STATUS
    // ========================================
    private static int StatusCommand()
    {
        var (provider, model, endpoint, _) = ReadLLMConfig();

        var table = new Table()
            .BorderColor(Color.Teal)
            .AddColumn("类别")
            .AddColumn("状态");

        var version = typeof(CliApp).Assembly.GetName().Version;
        var ver = version != null
            ? $"v{version.Major}.{version.Minor}.{version.Build}"
            : $"v{LucentMist.Core.AppVersion.Current}";
        table.AddRow("[grey]版本[/]", $"[green]{ver}[/]");
        table.AddRow("[grey]编译[/]", "[yellow]由 CI 验证[/]");
        table.AddRow("[grey]测试[/]", "[green]由 CI 验证[/]");
        table.AddRow("[grey]LLM[/]", $"[blue]{provider}[/] [green]{model}[/]");
        table.AddRow("[grey]地址[/]", $"[white]{endpoint}[/]");
        table.AddRow("[grey]工具[/]", "[blue]ping_scan[/] / [blue]port_scan[/] / [blue]service_identify[/] / [blue]os_fingerprint[/] / [blue]ssl_check[/] / [blue]udp_scan[/] / [blue]vuln_scan[/] / [blue]sirius_scan[/]");

        AnsiConsole.Write(new Panel(table)
            .Header("[teal] LucentMist [/]")
            .BorderColor(Color.Teal));
        return 0;
    }

    // ========================================
    // HELP
    // ========================================
    private static int HelpCommand()
    {
        var (provider, model, _, _) = ReadLLMConfig();

        AnsiConsole.Write(new FigletText("LucentMist")
            .Color(Color.Teal));

        AnsiConsole.MarkupLine("[grey]基于 ReAct 模式的智能网络分析助手[/]");
        AnsiConsole.MarkupLine($"[grey]当前 LLM: {provider} / {model}[/]\n");

        var table = new Table()
            .BorderColor(Color.Grey)
            .AddColumn("[teal]命令[/]")
            .AddColumn("[teal]说明[/]")
            .AddColumn("[teal]示例[/]");

        table.AddRow("[yellow]scan[/]", "网络扫描", "[grey]lmist scan 192.168.1.0/24 --udp[/]");
        table.AddRow("[yellow]ssl-check[/]", "SSL 证书校验", "[grey]lmist ssl-check baidu.com[/]");
        table.AddRow("[yellow]os-fingerprint[/]", "OS 指纹识别", "[grey]lmist os-fingerprint 192.168.1.1[/]");
        table.AddRow("[yellow]vuln-scan[/]", "漏洞扫描", "[grey]lmist vuln-scan 192.168.1.1[/]");
        table.AddRow("[yellow]vuln-detail[/]", "CVE 详情", "[grey]lmist vuln-detail CVE-2017-0144[/]");
        table.AddRow("[yellow]sirius[/]", "Sirius 漏洞", "[grey]lmist sirius summary|target|vuln|status[/]");
        table.AddRow("[yellow]report[/]", "生成报告", "[grey]lmist report --format html[/]");
        table.AddRow("[yellow]agent[/]", "AI 智能体对话", "[grey]lmist agent \"分析网络\"[/]");
        table.AddRow("[yellow]audit[/]", "查看扫描审计", "[grey]lmist audit --limit 50[/]");
        table.AddRow("[yellow]backup[/]", "安全备份数据", "[grey]lmist backup --output backups/me.db[/]");
        table.AddRow("[yellow]restore[/]", "恢复扫描数据", "[grey]lmist restore backups/me.db --yes[/]");
        table.AddRow("[yellow]config[/]", "查看/切换配置", "[grey]lmist config --set Model=qwen2.5:7b[/]");
        table.AddRow("[yellow]status[/]", "系统状态", "[grey]lmist status[/]");
        table.AddRow("[yellow]help[/]", "帮助信息", "[grey]lmist help[/]");

        AnsiConsole.Write(table);
        return 0;
    }

    private static int UnknownCommand(string command)
    {
        AnsiConsole.MarkupLine($"[red]未知命令: {Escape(command)}[/]");
        AnsiConsole.MarkupLine("[grey]运行 lmist help 查看可用命令[/]");
        return 1;
    }
}
