namespace LucentMist.Scanning;

/// <summary>读取扫描任务持久化状态，供监控客户端使用。</summary>
public interface IScanTaskReader
{
    Task<ScanTaskRecord?> GetAsync(string id);
}
