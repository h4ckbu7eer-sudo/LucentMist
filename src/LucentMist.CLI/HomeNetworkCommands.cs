using System.Text.Json;
using LucentMist.Scanning;
using LucentMist.Scanning.Monitoring;
using LucentMist.Tools.Scanning;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace LucentMist.CLI;

internal static class HomeNetworkCommands
{
    internal const string DefaultPorts = "22,53,80,135,139,443,445,3389,8080,8443";

    internal static Dictionary<string, string> Parse(string[] args, string[] flags, string[] values)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var pair = args[i].Split('=', 2);
            var key = pair[0];
            if (key == "--merge" && values.Contains(key))
            {
                var oldIdentity = pair.Length == 2 ? pair[1] : i + 1 < args.Length ? args[++i] : "";
                var newIdentity = i + 1 < args.Length ? args[++i] : "";
                if (string.IsNullOrWhiteSpace(oldIdentity) || string.IsNullOrWhiteSpace(newIdentity) ||
                    oldIdentity.StartsWith('-') || newIdentity.StartsWith('-')) throw new ArgumentException("用法：monitor --merge <旧IP/MAC> <新IP/MAC>");
                result.Add("--merge", oldIdentity);
                result.Add("--merge-target", newIdentity);
                continue;
            }
            if (flags.Contains(key) && pair.Length == 1) result.Add(key, "true");
            else if (values.Contains(key))
            {
                var value = pair.Length == 2 ? pair[1] : i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "";
                if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException($"{key} 缺少值");
                result.Add(key, value);
            }
            else throw new ArgumentException($"未知参数 {key}");
        }
        return result;
    }

    public static Task<int> MonitorAsync(string[] args, ILoggerFactory logger,
        Func<MonitorScope, bool, CancellationToken, Task<NetworkSnapshot>>? capture = null,
        Func<CancellationToken, Task<string>>? defaultSubnet = null) => WithCancellation(async ct =>
    {
        var options = Parse(args, ["--once", "--alerts", "--devices", "--check-vulns"], ["--interval", "--subnet", "--ports", "--trust", "--merge", "--cycles", "--limit"]);
        if (new[] { "--alerts", "--devices", "--trust", "--merge" }.Count(options.ContainsKey) > 1)
            throw new ArgumentException("--alerts、--devices、--trust 与 --merge 不能同时使用");
        if (options.ContainsKey("--merge") && new[] { "--once", "--cycles", "--interval", "--check-vulns" }.Any(options.ContainsKey))
            throw new ArgumentException("--merge 仅确认合并，不能与扫描参数同时使用。");
        var interval = Integer(options, "--interval", 30, 1, 1440);
        int? cycles = options.ContainsKey("--once") ? 1 : options.ContainsKey("--cycles") ? Integer(options, "--cycles", 1, 1, 10000) : null;
        if (options.ContainsKey("--once") && options.ContainsKey("--cycles")) throw new ArgumentException("--once 与 --cycles 不能同时使用");
        var subnet = options.GetValueOrDefault("--subnet");
        if (subnet == null && defaultSubnet != null) subnet = await defaultSubnet(ct);
        if (subnet == null)
        {
            var local = await new GetMyIpTool().ExecuteAsync(new(), ct);
            if (!local.Success) throw new ArgumentException(local.Error);
            using var data = JsonDocument.Parse(local.Data);
            subnet = data.RootElement.GetProperty("suggestedSubnet").GetString() ?? throw new ArgumentException("未取得物理主接口，请显式设置 --subnet");
        }
        var scope = MonitorScope.Create(subnet, options.GetValueOrDefault("--ports", DefaultPorts));
        var dbPath = Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db");
        // Reuse scan-store startup checks, audit history and the existing database/backup location.
        var audit = new ScanStore(dbPath);
        var store = new MonitorStore(dbPath);
        var queryOnly = new[] { "--alerts", "--devices", "--trust", "--merge" }.Any(options.ContainsKey);
        AnsiConsole.MarkupLine($"[teal]家庭监控：{Markup.Escape(scope.Subnet)}{(queryOnly ? "（查询此网段的全部记录）" : "; TCP " + Markup.Escape(scope.Ports))}[/]");
        if (options.TryGetValue("--merge", out var oldIdentity))
        {
            using var mergeLease = NetworkMonitor.AcquireLease(dbPath, scope);
            var merged = store.Merge(scope, oldIdentity, options["--merge-target"], DateTimeOffset.UtcNow);
            AnsiConsole.MarkupLine($"[green]已确认合并到 {Markup.Escape(merged.Device.Ip)}；{(merged.Trusted ? "信任已迁移" : "两端均未信任，不自动设为可信")}；首次出现与端口历史已保留。[/]");
            RenderDevices(store.ListDevices(scope));
            return 0;
        }
        if (options.TryGetValue("--trust", out var identity))
        {
            var mac = store.Trust(scope, identity);
            AnsiConsole.MarkupLine($"[green]已信任 MAC {Markup.Escape(mac)}（仅当前基线范围；MAC 可随机化/伪造）[/]");
            return 0;
        }
        if (options.ContainsKey("--devices")) { RenderDevices(store.ListDevices(scope)); return 0; }
        if (options.ContainsKey("--alerts"))
        {
            RenderAnalysisStatus(store.ListDevices(scope));
            var alerts = store.ListAlerts(scope, Integer(options, "--limit", 100, 1, 1000));
            if (alerts.Length == 0) AnsiConsole.MarkupLine("[grey]当前范围暂无已记录告警；不代表已完成全面安全检查。[/]");
            RenderAlerts(alerts);
            return 0;
        }
        FileStream lease;
        try { lease = NetworkMonitor.AcquireLease(dbPath, scope); }
        catch (IOException) { throw new IOException("此数据库/扫描范围已有监控在运行，或无法创建锁文件；请检查后重试。"); }
        using (lease)
        {
            var lastApplied = false;
            var vulnerability = options.ContainsKey("--check-vulns");
            AnsiConsole.MarkupLine("[yellow]" + ScheduleDescription(cycles, interval) + "仅监控+告警+建议，不自动修复或隔离。[/]");
            AnsiConsole.MarkupLine(vulnerability
                ? "[yellow]已启用漏洞候选检查，云源开关沿用 LMIST_CVE_EXTERNAL；候选不是确认漏洞。[/]"
                : "[grey]默认检查设备/端口/服务变化；不会声称已检查漏洞。需要时添加 --check-vulns。[/]");
            var scanner = new NetworkMonitorScanner(logger);
            var loop = new NetworkMonitor(store, token => capture != null ? capture(scope, vulnerability, token) : scanner.CaptureAsync(scope, vulnerability, token));
            await loop.RunAsync(scope, TimeSpan.FromMinutes(interval), cycles, async update =>
            {
                lastApplied = update.Applied;
                AnsiConsole.MarkupLine($"[teal]{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {Markup.Escape(update.Summary)}[/]");
                if (update.BaselineCreated) AnsiConsole.MarkupLine("[green]已建立首轮基线（不自动代表可信），请核对设备并使用 --trust 标记。[/]");
                RenderDevices(update.Devices);
                RenderAlerts(update.Alerts);
                await audit.AppendAuditAsync(Guid.NewGuid().ToString("N"), null, scope.Subnet, "cli-monitor", "monitor", update.Applied ? "completed" : "failed", update.Summary, ct);
            }, ct);
            return lastApplied ? 0 : 2;
        }
    });

    public static Task<int> DiagnoseAsync(string[] args) => WithCancellation(async ct =>
    {
        var options = Parse(args, ["--no-external", "--all-listeners"], ["--gateway", "--dns-name"]);
        if (options.TryGetValue("--gateway", out var gateway)) ValidateGateway(gateway);
        AnsiConsole.MarkupLine("[teal]基础网络诊断：接口 → 网关 → DNS → 公网 TCP → 本地监听[/]");
        AnsiConsole.MarkupLine("[grey]默认查询 example.com；公网 TCP 检查 1.1.1.1:443、8.8.8.8:53、223.5.5.5:53，不上传扫描报告。--no-external 禁用这些 TCP 检查（DNS 查询仍执行）。[/]");
        var report = await new NetworkDiagnostics().RunAsync(options.GetValueOrDefault("--gateway"), options.GetValueOrDefault("--dns-name", "example.com"), !options.ContainsKey("--no-external"), ct, options.ContainsKey("--all-listeners"));
        var table = new Table().AddColumn("层次").AddColumn("状态").AddColumn("实际证据");
        foreach (var check in report.Checks) table.AddRow(Markup.Escape(check.Layer), Markup.Escape(check.Status), Markup.Escape(check.Evidence));
        AnsiConsole.Write(table);
        foreach (var advice in report.Suggestions) AnsiConsole.MarkupLine("[yellow]建议：" + Markup.Escape(advice) + "[/]");
        return report.Checks.Any(c => c.Status is "failed" or "warning") ? 2 : 0;
    });

    private static int Integer(Dictionary<string, string> args, string key, int defaultValue, int min, int max)
    {
        if (!args.TryGetValue(key, out var text)) return defaultValue;
        if (!int.TryParse(text, out var value) || value < min || value > max) throw new ArgumentException($"{key} 必须为 {min}～{max} 的整数");
        return value;
    }
    internal static void ValidateGateway(string gateway)
    {
        if (!System.Net.IPAddress.TryParse(gateway, out var ip) || ip.GetAddressBytes().Length != 4)
            throw new ArgumentException("--gateway 必须是单个局域网 IPv4 地址，不是网段或域名");
        MonitorScope.Create(gateway, "443");
    }
    private static void RenderDevices(IEnumerable<KnownDevice> devices)
    {
        var items = devices.ToArray();
        var rows = MonitorDevicePresentation.Rows(items);
        AnsiConsole.MarkupLine("[grey]以下为数据库最近有效记录，不是实时在线保证；端口保留各自观测时间。[/]");
        RenderTable(rows.Where(r => r.Item.Present).ToArray(), "最近观测设备");
        foreach (var row in rows.Where(r => r.Replaced.Length > 0))
        {
            var oldIps = string.Join("、", row.Replaced.Select(d => d.Device.Ip).Distinct());
            var tentative = row.Item.Association?.Status == "possible_same_device";
            AnsiConsole.MarkupLine($"[yellow]旧 {Markup.Escape(oldIps)} 已被 {Markup.Escape(row.Item.Device.Ip)} 取代{(tentative ? "（疑似，尚未合并/迁移信任）" : "（用户已确认合并，旧身份已归档）")}。[/]");
        }
        var offline = rows.Where(r => !r.Item.Present).ToArray();
        if (offline.Length > 0)
        {
            AnsiConsole.MarkupLine($"[grey]离线设备（{offline.Length}）：以下是历史记录，不与当前设备并列；未响应不等于确认断开。[/]");
            var history = new Table().AddColumn("历史 IP").AddColumn("名称/关联").AddColumn("最后出现");
            foreach (var row in offline) history.AddRow(Markup.Escape(row.Item.Device.Ip), Markup.Escape(row.Item.Device.Name + "\n" + row.Label),
                row.Item.LastSeen.ToLocalTime().ToString("MM-dd HH:mm:ss"));
            AnsiConsole.Write(history);
        }
        RenderAnalysisStatus(items);
    }
    private static void RenderTable(MonitorDeviceRow[] rows, string title)
    {
        AnsiConsole.MarkupLine($"[teal]{title}（{rows.Length}）[/]");
        var table = new Table().AddColumn("IP/MAC").AddColumn("设备/厂商").AddColumn("最近记录/信任").AddColumn("已观测端口");
        foreach (var row in rows)
        {
            var item = row.Item;
            var description = DeviceDescription(item.Device);
            if (row.Label.Length > 0) description = description.Insert(item.Device.Name.Length, "\n" + row.Label);
            var status = row.Label.Length > 0 && item.Association?.Status is "possible_same_device" or "confirmed_same_device"
                ? item.Trusted ? "观测到/可信\n已显式信任\n当前 MAC"
                    : item.Association.Status == "confirmed_same_device" ? "观测到/未信任\n原身份也未信任" : "观测到/未信任\n不继承信任"
                : IdentityObservation(item);
            table.AddRow(Markup.Escape(item.Device.Ip + "\n" + (item.Device.Mac ?? "无 MAC")), Markup.Escape(description),
                Markup.Escape(status) + $"\n首次 {item.FirstSeen.ToLocalTime():MM-dd HH:mm:ss}\n最后 {item.LastSeen.ToLocalTime():MM-dd HH:mm:ss}", Markup.Escape(PortObservation(item)));
        }
        AnsiConsole.Write(table);
    }
    internal static string ScheduleDescription(int? cycles, int interval) => cycles == 1
        ? "仅执行一轮，完成后退出；Ctrl+C 可停止。"
        : $"两轮之间等待 {interval} 分钟；Ctrl+C 停止。";

    internal static string DeviceDescription(MonitorDevice device) => device.Name + "\n" + device.Vendor +
        (string.IsNullOrWhiteSpace(device.Model) ? "" : "\n型号：" + device.Model) +
        (device.MdnsServices?.Length > 0 ? "\nmDNS 声明：" + string.Join(", ", device.MdnsServices.Select(s => s.Replace("._tcp.local", "", StringComparison.Ordinal))) + "（非型号确认）" : "");

    internal static string[] AnalysisStatus(IEnumerable<KnownDevice> devices) => devices
        .Where(d => d.Present).SelectMany(d => (d.Device.Warnings ?? []).Select(w => d.Device.Ip + "：" + w)).Distinct().ToArray();

    private static void RenderAnalysisStatus(IEnumerable<KnownDevice> devices)
    {
        var notes = AnalysisStatus(devices);
        if (notes.Length == 0) return;
        AnsiConsole.MarkupLine("[yellow]检查状态：部分服务/漏洞分析未完成（不是变化告警）；没有漏洞候选不代表安全。[/]");
        foreach (var note in notes.Take(3)) AnsiConsole.MarkupLine("[grey]" + Markup.Escape(note) + "[/]");
        if (notes.Length > 3) AnsiConsole.MarkupLine($"[grey]另有 {notes.Length - 3} 条状态说明保存在设备最近记录中。[/]");
    }
    internal static string IdentityObservation(KnownDevice item) => !item.IdentityConfirmed
        ? "本轮身份未确认/信任不适用于当前响应"
        : item.Association is { } association
            ? (item.Present ? "观测到" : "历史记录") + (item.Trusted ? "\n已显式信任\n当前 MAC" : "/未信任\n不继承信任") +
                "\n" + association.Evidence + (association.RelatedDeviceIds.Length == 0 ? "" : "\n关联历史：" + string.Join(", ", association.RelatedDeviceIds))
            : (item.Present ? "观测到" : "未观测到") + (item.Trusted ? "/可信" : "/未信任");
    internal static string PortObservation(KnownDevice item) => item.Device.OpenPorts == null ? "未取得成功结果" :
        (item.Device.OpenPorts.Length == 0 ? "所选端口无成功连接" : string.Join(',', item.Device.OpenPorts)) +
        (!item.IdentityConfirmed ? "（本轮身份未确认，保留历史）" : item.LastPortScanSucceeded ? "" : "（本次扫描失败，保留历史）") +
        $"\n最近成功范围 {item.LastPortScope ?? "未记录"}，观测于 {item.PortsObservedAt?.ToLocalTime():MM-dd HH:mm:ss}" +
        (item.PortHistory?.Values.Select(p => p.At).Distinct().Skip(1).Any() == true ? "\n含其它轮次端口历史，未扫描端口不推断关闭" : "");
    private static void RenderAlerts(IEnumerable<MonitorAlert> alerts)
    {
        foreach (var alert in alerts)
        {
            var color = alert.Priority == "high" ? "red" : alert.Priority == "medium" ? "yellow" : "grey";
            AnsiConsole.MarkupLine($"[{color}]#{alert.Id} {alert.At.ToLocalTime():MM-dd HH:mm:ss} {alert.Priority} {Markup.Escape(alert.Ip)} {Markup.Escape(alert.Kind)}：{Markup.Escape(alert.Message.Replace("运行 monitor --merge ", "\n运行 monitor --merge ", StringComparison.Ordinal))}[/]");
        }
    }
    private static async Task<int> WithCancellation(Func<CancellationToken, Task<int>> run)
    {
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stop.Cancel(); };
        Console.CancelKeyPress += handler;
        try { return await run(stop.Token); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { AnsiConsole.MarkupLine("[grey]已停止；已提交的基线/告警保留。[/]"); return 0; }
        catch (Exception ex) when (ex is ArgumentException or IOException or SqliteException or UnauthorizedAccessException)
        { AnsiConsole.MarkupLine("[red]" + Markup.Escape(ex.Message) + "[/]"); return 1; }
        finally { Console.CancelKeyPress -= handler; }
    }
}
