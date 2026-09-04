using System.Collections.Concurrent;
using LucentMist.Tools.Reporting;

namespace LucentMist.CLI;

internal static class ReportDeviceCollector
{
    internal static async Task<IReadOnlyList<ReportDeviceScanResult>> CollectAsync(
        IReadOnlyList<string> devices,
        Func<string, CancellationToken, Task<ReportDeviceScanResult>> scanDeviceAsync,
        int maxDegreeOfParallelism,
        CancellationToken cancellationToken = default)
    {
        if (devices.Count == 0)
            return [];

        var degree = Math.Clamp(maxDegreeOfParallelism, 1, 8);
        var results = new ConcurrentDictionary<int, ReportDeviceScanResult>();
        var indexedDevices = devices.Select((target, index) => (target, index));

        await Parallel.ForEachAsync(
            indexedDevices,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = degree,
                CancellationToken = cancellationToken
            },
            async (item, ct) =>
            {
                results[item.index] = await scanDeviceAsync(item.target, ct);
            });

        return Enumerable.Range(0, devices.Count)
            .Select(index => results[index])
            .ToArray();
    }
}

internal sealed record ReportDeviceScanResult(
    ReportGenerator.DeviceEntry Device,
    IReadOnlyList<ReportGenerator.PortEntry> OpenPorts,
    IReadOnlyList<ReportGenerator.SslEntry> SslInfo,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> Notes,
    PortScanEvidenceStatus PortScanStatus = PortScanEvidenceStatus.Succeeded,
    string? PortScanError = null);

internal enum PortScanEvidenceStatus
{
    NotRun,
    Succeeded,
    Failed,
}
