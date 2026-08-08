using LucentMist.Core.Models;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Actors;

/// <summary>
/// 扫描 Actor 消息
/// </summary>
public record StartScan(string TaskId, string Target, string ScanType);
public record ScanProgress(string TaskId, int Scanned, int Total, int Alive);
public record ScanCompleted(string TaskId, List<ScanResult> Results);
public record ScanFailed(string TaskId, string Error);

/// <summary>
/// 扫描执行 Actor — 通过注入的 IScanner 调用真实扫描，结果回发发起者。
/// 职责边界：API 的 ScanWorker 是后台队列入口；本 Actor 供未来多会话/调度复用。
/// </summary>
public class ScannerActor : BaseActor
{
    private readonly IScanner _scanner;

    public ScannerActor(IScanner scanner, ILoggerFactory loggerFactory) : base(loggerFactory)
    {
        _scanner = scanner;
        Receive<StartScan>(HandleStartScan);
    }

    private void HandleStartScan(StartScan msg)
    {
        Logger.LogInformation("ScannerActor 收到扫描任务: TaskId={TaskId}, Target={Target}, Type={ScanType}",
            msg.TaskId, msg.Target, msg.ScanType);

        var sender = Sender;
        var self = Self;

        // 同步捕获 Sender，异步执行真实扫描，结果回发发起者
        _ = Task.Run(async () =>
        {
            try
            {
                sender.Tell(new ScanProgress(msg.TaskId, 0, 1, 0), self);

                var ok = await _scanner.ScanAsync(msg.Target);

                sender.Tell(ok
                    ? new ScanCompleted(msg.TaskId, [])
                    : new ScanFailed(msg.TaskId, "扫描未成功完成"), self);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "ScannerActor 扫描异常: TaskId={TaskId}", msg.TaskId);
                sender.Tell(new ScanFailed(msg.TaskId, ex.Message), self);
            }
        });
    }
}
