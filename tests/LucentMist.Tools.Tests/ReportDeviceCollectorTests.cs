using System.Diagnostics;
using LucentMist.CLI;
using LucentMist.Tools.Reporting;
using Xunit.Abstractions;

namespace LucentMist.Tools.Tests;

public sealed class ReportDeviceCollectorTests(ITestOutputHelper output)
{
    [Fact]
    public async Task CollectAsync_TenDevices_IsBoundedAndFasterThanSequential()
    {
        var devices = Enumerable.Range(1, 10).Select(index => $"device-{index}").ToArray();
        const int delayMs = 100;
        var active = 0;
        var maximumActive = 0;

        async Task<ReportDeviceScanResult> ScanAsync(
            string target,
            CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref active);
            UpdateMaximum(ref maximumActive, current);
            try
            {
                await Task.Delay(delayMs, cancellationToken);
                return new ReportDeviceScanResult(
                    new ReportGenerator.DeviceEntry { Ip = target, IsAlive = true },
                    [],
                    [],
                    [],
                    []);
            }
            finally
            {
                Interlocked.Decrement(ref active);
            }
        }

        var parallelTimer = Stopwatch.StartNew();
        var results = await ReportDeviceCollector.CollectAsync(
            devices,
            ScanAsync,
            maxDegreeOfParallelism: 4);
        parallelTimer.Stop();

        var sequentialTimer = Stopwatch.StartNew();
        foreach (var device in devices)
            await Task.Delay(delayMs);
        sequentialTimer.Stop();

        var speedup = sequentialTimer.Elapsed.TotalMilliseconds
            / parallelTimer.Elapsed.TotalMilliseconds;
        output.WriteLine(
            $"10 devices: sequential={sequentialTimer.Elapsed.TotalMilliseconds:F0}ms, " +
            $"bounded-parallel={parallelTimer.Elapsed.TotalMilliseconds:F0}ms, " +
            $"speedup={speedup:F2}x, max-active={maximumActive}");

        Assert.Equal(devices, results.Select(result => result.Device.Ip));
        Assert.InRange(maximumActive, 2, 4);
        Assert.True(speedup >= 2.0, $"Expected >=2x speedup, observed {speedup:F2}x");
    }

    private static void UpdateMaximum(ref int maximum, int candidate)
    {
        var current = Volatile.Read(ref maximum);
        while (candidate > current)
        {
            var observed = Interlocked.CompareExchange(ref maximum, candidate, current);
            if (observed == current)
                return;
            current = observed;
        }
    }
}
