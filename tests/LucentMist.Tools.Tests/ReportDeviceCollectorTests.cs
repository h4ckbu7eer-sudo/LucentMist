using LucentMist.CLI;
using LucentMist.Tools.Reporting;
using Xunit.Abstractions;

namespace LucentMist.Tools.Tests;

public sealed class ReportDeviceCollectorTests(ITestOutputHelper output)
{
    [Fact]
    public async Task CollectAsync_TenDevices_UsesBoundedParallelismAndPreservesOrder()
    {
        var devices = Enumerable.Range(1, 10).Select(index => $"device-{index}").ToArray();
        const int maxDegreeOfParallelism = 4;
        var active = 0;
        var maximumActive = 0;
        var allSlotsActive = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseScans = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        async Task<ReportDeviceScanResult> ScanAsync(
            string target,
            CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref active);
            UpdateMaximum(ref maximumActive, current);
            if (current == maxDegreeOfParallelism)
                allSlotsActive.TrySetResult(true);

            try
            {
                await releaseScans.Task.WaitAsync(cancellationToken);
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

        var collectionTask = ReportDeviceCollector.CollectAsync(
            devices,
            ScanAsync,
            maxDegreeOfParallelism);

        try
        {
            await allSlotsActive.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(collectionTask.IsCompleted);
            Assert.Equal(maxDegreeOfParallelism, Volatile.Read(ref maximumActive));
            Assert.InRange(Volatile.Read(ref active), 1, maxDegreeOfParallelism);
        }
        finally
        {
            releaseScans.TrySetResult(true);
        }

        var results = await collectionTask.WaitAsync(TimeSpan.FromSeconds(5));
        output.WriteLine(
            $"10 devices: max-active={maximumActive}, " +
            $"bounded waves={Math.Ceiling(devices.Length / (double)maxDegreeOfParallelism):F0}, " +
            $"sequential waves={devices.Length}");

        Assert.Equal(devices, results.Select(result => result.Device.Ip));
        Assert.Equal(maxDegreeOfParallelism, maximumActive);
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
