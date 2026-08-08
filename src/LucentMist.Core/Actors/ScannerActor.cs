namespace LucentMist.Core.Actors;

/// <summary>扫描调度消息类型。后台扫描统一由 ScanWorker 执行，此处保留消息供未来调度复用。</summary>
public record StartScan(string TaskId, string Target, string ScanType);
public record ScanProgress(string TaskId, int Scanned, int Total, int Alive);
public record ScanCompleted(string TaskId, List<LucentMist.Core.Models.ScanResult> Results);
public record ScanFailed(string TaskId, string Error);
