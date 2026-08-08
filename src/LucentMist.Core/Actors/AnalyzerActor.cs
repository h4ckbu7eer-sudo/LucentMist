using LucentMist.Core.Models;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Actors;

/// <summary>
/// 分析 Actor 消息
/// </summary>
public record AnalyzeResults(string TaskId, List<ScanResult> Results);
public record AnalysisCompleted(string TaskId, List<Alert> Alerts, string Summary);

/// <summary>
/// 分析执行 Actor — 对扫描结果进行分析，生成告警和摘要
/// </summary>
public class AnalyzerActor : BaseActor
{
    public AnalyzerActor(ILoggerFactory loggerFactory) : base(loggerFactory)
    {
        Receive<AnalyzeResults>(HandleAnalyze);
    }

    private void HandleAnalyze(AnalyzeResults msg)
    {
        Logger.LogInformation("AnalyzerActor 开始分析: TaskId={TaskId}, DeviceCount={Count}",
            msg.TaskId, msg.Results.Count);

        var alerts = new List<Alert>();
        var aliveCount = msg.Results.Count(r => r.IsAlive);
        var serviceCount = msg.Results.Sum(r => r.OpenPorts.Length);

        var summary = $"扫描完成：共扫描 {msg.Results.Count} 个目标，{aliveCount} 个在线，" +
                      $"发现 {serviceCount} 个开放端口";

        if (aliveCount == 0)
        {
            alerts.Add(new Alert
            {
                AlertType = Alert.Types.Offline,
                Severity = Alert.Severities.Warning,
                Title = "未发现存活设备",
                Description = $"目标 {msg.Results.FirstOrDefault()?.IpAddress ?? "unknown"} 无设备响应"
            });
        }

        Sender.Tell(new AnalysisCompleted(msg.TaskId, alerts, summary), Self);
    }
}
