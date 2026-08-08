namespace LucentMist.Scanning;

/// <summary>扫描任务协调器 — 提交任务立即返回 taskId，后台排队执行。</summary>
public interface IScanCoordinator
{
    /// <summary>入队扫描任务，立即返回 taskId。</summary>
    Task<string> StartAsync(
        string target,
        string scanType = "ping",
        string ports = "",
        CancellationToken ct = default);
}
