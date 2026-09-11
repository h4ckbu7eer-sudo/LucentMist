using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using LucentMist.Scanning.Monitoring;
using LucentMist.Tools.Discovery;
using Spectre.Console;

namespace LucentMist.CLI;

internal static partial class HomeNetworkCommands
{
    private static async Task<int> SniffDhcpAsync(string[] args, CancellationToken ct)
    {
        var options = Parse(args, ["--passive", "--no-elevate", "--json"],
            ["--subnet", "--dhcp-pipe", "--timeout-ms", "--retries", "--interval-ms", "--passive-ms"]);
        var subnet = options.GetValueOrDefault("--subnet") ?? throw new ArgumentException("用法：monitor sniff-dhcp --subnet <本机私有子网/CIDR>");
        subnet = MonitorScope.Create(subnet, "67,68").Subnet;
        var defaults = DhcpProbeOptions.FromEnvironment();
        var budget = new DhcpProbeOptions(Integer(options, "--timeout-ms", defaults.TimeoutMs, 250, 10000),
            Integer(options, "--retries", defaults.Retries, 1, 3), Integer(options, "--interval-ms", defaults.IntervalMs, 250, 5000),
            Integer(options, "--passive-ms", defaults.PassiveMs, 250, 120000));
        DhcpCaptureResult result;
        if (options.TryGetValue("--dhcp-pipe", out var pipeId))
        {
            if (!Guid.TryParseExact(pipeId, "N", out _)) throw new ArgumentException("无效的 DHCP 子进程通道。");
            // This child accepts no output path and never opens the monitor DB.
            // Only the requesting Windows user can connect to the pipe server.
            using var pipe = new NamedPipeClientStream(".", "lmist-dhcp-" + pipeId, PipeDirection.Out,
                PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
            await pipe.ConnectAsync(10000, ct);
            result = await DhcpProbe.CaptureAsync(subnet, ct, options.ContainsKey("--passive"), budget);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(result);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
            await pipe.WriteAsync(header, ct);
            await pipe.WriteAsync(bytes, ct);
            await pipe.FlushAsync(ct);
        }
        else
        {
            result = await CaptureDhcpAsync(subnet, options.ContainsKey("--passive"), ct, budget,
                !options.ContainsKey("--no-elevate"), !options.ContainsKey("--json"));
            if (options.ContainsKey("--json")) Console.WriteLine(JsonSerializer.Serialize(result));
            else RenderDhcp(result);
        }
        return result.Records.Length > 0 ? 0 : 2;
    }

    private static async Task<DhcpCaptureResult> CaptureDhcpAsync(string subnet, bool passiveOnly, CancellationToken ct,
        DhcpProbeOptions? options = null, bool allowElevation = true, bool display = true)
    {
        options ??= DhcpProbeOptions.FromEnvironment();
        var result = await DhcpProbe.CaptureAsync(subnet, ct, passiveOnly, options);
        if (result.Status != "permission-required" || !allowElevation) return result;
        const string notice = "本命令需要管理员权限以监听 DHCP，正在请求 UAC；仅短时采集子进程提权，主监控不提权。拒绝后保留原扫描结果。";
        if (display) AnsiConsole.MarkupLine("[yellow]" + notice + "[/]");
        else Console.Error.WriteLine(notice);
        return await ElevateDhcpAsync(subnet, passiveOnly, options, ct);
    }

    internal static ProcessStartInfo DhcpChildStart(string executable, string assembly, string subnet, string pipeId,
        bool passiveOnly, DhcpProbeOptions options)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Environment.CurrentDirectory,
        };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(assembly);
        foreach (var arg in new[] { "monitor", "sniff-dhcp", "--subnet", subnet, "--dhcp-pipe", pipeId,
            "--timeout-ms", options.TimeoutMs.ToString(), "--retries", options.Retries.ToString(),
            "--interval-ms", options.IntervalMs.ToString(), "--passive-ms", options.PassiveMs.ToString() }) start.ArgumentList.Add(arg);
        if (passiveOnly) start.ArgumentList.Add("--passive");
        return start;
    }

    private static async Task<DhcpCaptureResult> ElevateDhcpAsync(string subnet, bool passiveOnly, DhcpProbeOptions options, CancellationToken ct)
    {
        var pipeId = Guid.NewGuid().ToString("N");
        using var pipe = new NamedPipeServerStream("lmist-dhcp-" + pipeId, PipeDirection.In, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var responseTimeout = TimeSpan.FromMilliseconds(options.Retries * (options.TimeoutMs + options.IntervalMs) + options.PassiveMs + 30000);
        var executable = Environment.ProcessPath ?? throw new IOException("无法确定当前执行文件，未提权。");
        var assembly = Assembly.GetEntryAssembly()?.Location ?? throw new IOException("无法确定 CLI 程序集，未提权。");
        var phase = "UAC 启动";
        var elapsed = Stopwatch.StartNew();
        try
        {
            return await RunDhcpChildAsync(() => Process.Start(DhcpChildStart(executable, assembly, subnet, pipeId, passiveOnly, options))
                ?? throw new IOException("无法启动 DHCP 采集子进程。"), async (child, token) =>
                {
                    phase = "管道连接";
                    var connected = pipe.WaitForConnectionAsync(token);
                    var exited = child.WaitForExitAsync(token);
                    if (await Task.WhenAny(connected, exited) == exited && !pipe.IsConnected)
                        return new("elevation-failed", "DHCP 子进程未返回数据即退出；未声称采集成功。", []);
                    await connected;
                    phase = "结果回传";
                    var header = new byte[4];
                    await pipe.ReadExactlyAsync(header, token);
                    var length = BinaryPrimitives.ReadInt32LittleEndian(header);
                    if (length is < 2 or > 2097152) throw new InvalidDataException("DHCP 子进程返回数据长度无效。");
                    var bytes = new byte[length];
                    await pipe.ReadExactlyAsync(bytes, token);
                    return JsonSerializer.Deserialize<DhcpCaptureResult>(bytes) ?? throw new InvalidDataException("DHCP 子进程未返回有效结果。");
                }, responseTimeout, ct);
        }
        catch (Win32Exception ex)
        {
            return new(ex.NativeErrorCode == 1223 ? "elevation-declined" : "elevation-failed",
                $"UAC 未获批准或启动失败（{ex.NativeErrorCode}）；本轮未采集 DHCP，监控主进程未提权。", []);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new("elevation-timeout", $"DHCP {phase}超时（累计 {elapsed.Elapsed.TotalSeconds:F0} 秒）；未取得结果。子进程采集窗口有独立上限，不长期监听。", []);
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return new("elevation-failed", $"DHCP 子进程结果读取失败（{ex.GetType().Name}）；不报告成功。", []);
        }
    }

    internal static async Task<DhcpCaptureResult> RunDhcpChildAsync(Func<Process> launch,
        Func<Process, CancellationToken, Task<DhcpCaptureResult>> receive, TimeSpan responseTimeout, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var child = launch();
        // ShellExecute may wait for UAC approval. Only the receive budget starts
        // here; the caller's cancellation/deadline still covers the whole scan.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(responseTimeout);
        try
        {
            budget.Token.ThrowIfCancellationRequested();
            return await receive(child, budget.Token);
        }
        finally { await budget.CancelAsync(); }
    }

    internal static void RenderDhcp(DhcpCaptureResult result)
    {
        AnsiConsole.MarkupLine($"[teal]DHCP {Markup.Escape(result.Status)}；接口 {Markup.Escape(result.InterfaceIp ?? "未取得")}；DISCOVER 已发送 {result.DiscoverSent} 次[/]");
        AnsiConsole.MarkupLine(Markup.Escape(result.Message));
        var table = new Table().AddColumn("来源 IP / 类型").AddColumn("hostname (12)").AddColumn("vendorClass (60)").AddColumn("MAC").AddColumn("sourceMode");
        foreach (var record in result.Records)
            table.AddRow(Markup.Escape(record.SourceIp + " / " + record.MessageType), Markup.Escape(record.Hostname ?? "未公开"),
                Markup.Escape(record.VendorClass ?? "未公开"), Markup.Escape(record.Mac), Markup.Escape(record.SourceMode));
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]字段为未认证报文原文；随机/本地管理 MAC 的 hostname 已知不代表厂商确认。0.0.0.0 是未分配地址客户端的真实源 IP，不是当前租约 IP。--json 可导出完整记录及 DHCP 原始十六进制报文。[/]");
    }
}
