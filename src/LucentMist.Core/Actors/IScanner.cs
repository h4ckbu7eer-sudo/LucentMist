namespace LucentMist.Core.Actors;

/// <summary>
/// 扫描执行接口 — Core 只定义契约，实现由宿主（API/CLI）注入。
/// 避免 Core 反向依赖 Tools。
/// </summary>
public interface IScanner
{
    /// <summary>执行一次存活扫描，返回是否成功（结果由实现方回传）</summary>
    Task<bool> ScanAsync(string target, CancellationToken ct = default);
}
