using LucentMist.CLI;
using LucentMist.Tools.Common;
using LucentMist.Tools.Reporting;
using LucentMist.Tools.Security;
using Xunit.Abstractions;

namespace LucentMist.Tools.Tests;

public sealed class ReportDeviceCollectorTests(ITestOutputHelper output)
{
    [Fact]
    public void ReportTcpPortSelection_CoversBaseRangeAndSupplementalRiskPortsOnce()
    {
        Assert.True(PortHelper.TryParsePorts(CliApp.ReportTcpPortSelection, out var ports));
        Assert.Contains(1, ports);
        Assert.Contains(1000, ports);
        foreach (var port in VulnerabilityScanTool.DefaultScanPorts)
            Assert.Contains(port, ports);
        Assert.Equal(ports.Count, ports.Distinct().Count());
    }

    [Fact]
    public void BuildReportVulnerabilityArguments_PreservesSucceededEmptyAndObservedStates()
    {
        var empty = new ReportDeviceScanResult(
            new ReportGenerator.DeviceEntry { Ip = "192.168.1.10" }, [], [], [], []);
        var observed = new ReportDeviceScanResult(
            new ReportGenerator.DeviceEntry { Ip = "192.168.1.11" },
            [
                new ReportGenerator.PortEntry { Target = "192.168.1.11", Port = 443 },
                new ReportGenerator.PortEntry { Target = "192.168.1.11", Port = 53 },
            ], [], [], []);

        var emptyArgs = CliApp.BuildReportVulnerabilityArguments(empty);
        var observedArgs = CliApp.BuildReportVulnerabilityArguments(observed);

        Assert.True(emptyArgs.ContainsKey("open_ports"));
        Assert.Equal("", emptyArgs["open_ports"]);
        Assert.Equal("succeeded", emptyArgs["port_scan_status"]);
        Assert.Equal("443,53", observedArgs["open_ports"]);
        Assert.Equal("succeeded", observedArgs["port_scan_status"]);
        Assert.False(emptyArgs.ContainsKey("ports"));
        Assert.False(observedArgs.ContainsKey("ports"));
    }

    [Fact]
    public async Task BuildReportVulnerabilityArguments_FailedScanCannotBecomeEmptySuccess()
    {
        var failed = new ReportDeviceScanResult(
            new ReportGenerator.DeviceEntry { Ip = "192.168.1.12" },
            [], [], ["端口扫描失败"], [],
            PortScanEvidenceStatus.Failed,
            "连接资源耗尽");

        var arguments = CliApp.BuildReportVulnerabilityArguments(failed);

        Assert.Equal("failed", arguments["port_scan_status"]);
        Assert.Equal("连接资源耗尽", arguments["port_scan_error"]);
        Assert.False(arguments.ContainsKey("open_ports"));

        var result = await new VulnerabilityScanTool().ExecuteAsync(arguments);
        Assert.False(result.Success);
        Assert.Contains("前置端口扫描失败", result.Error);
        Assert.DoesNotContain("未观测到开放服务", result.Error);
    }

    [Fact]
    public void ApplyPortScanEvidence_NotRunOmitsOpenPortsSoDiscoveryRemainsUnknown()
    {
        var arguments = new ToolArguments { ["open_ports"] = "" };

        CliApp.ApplyPortScanEvidence(arguments, PortScanEvidenceStatus.NotRun, []);

        Assert.Equal("not_run", arguments["port_scan_status"]);
        Assert.False(arguments.ContainsKey("open_ports"));
    }

    [Fact]
    public async Task ResolveExplicitReportTarget_InconclusiveDiscoveryContinuesOnlyForSingleTarget()
    {
        Assert.Equal("127.0.0.1", await CliApp.ResolveExplicitReportTargetAsync("127.0.0.1"));
        Assert.Null(await CliApp.ResolveExplicitReportTargetAsync("127.0.0.0/24"));
    }

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
