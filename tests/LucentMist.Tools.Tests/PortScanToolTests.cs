using LucentMist.Tools.Scanning;

namespace LucentMist.Tools.Tests;

public class PortScanToolTests
{
    [Fact]
    public void Tool_Name_ReturnsPortScan() =>
        Assert.Equal("port_scan", CreateTool().Name);

    [Fact]
    public async Task Execute_EmptyTarget_Fails()
    {
        var r = await CreateTool().ExecuteAsync(new() { ["target"] = "" });
        Assert.False(r.Success);
    }

    [Fact]
    public async Task Execute_CanceledToken_PropagatesCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateTool().ExecuteAsync(
                new() { ["target"] = "127.0.0.1", ["ports"] = "80" },
                cts.Token));
    }

    [Fact]
    public async Task Execute_ContainsRequiredFields()
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "80,443",
            ["timeout_ms"] = "1000"
        });
        Assert.True(r.Success);
        Assert.Contains("target", r.Data);
        Assert.Contains("totalScanned", r.Data);
        Assert.Contains("openPorts", r.Data);
    }

    [Fact]
    public async Task Execute_DashRange_CountsThree()
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "80-82",
            ["timeout_ms"] = "500"
        });
        Assert.Contains("\"totalScanned\":3", r.Data);
    }

    [Fact]
    public async Task Execute_CommaPorts_CountsThree()
    {
        var r = await CreateTool().ExecuteAsync(new()
        {
            ["target"] = "127.0.0.1",
            ["ports"] = "22,80,443",
            ["timeout_ms"] = "500"
        });
        Assert.Contains("\"totalScanned\":3", r.Data);
    }

    [Fact]
    public async Task Execute_Concurrent_NoCrash()
    {
        var tool = CreateTool();
        var tasks = Enumerable.Range(0, 3).Select(_ =>
            tool.ExecuteAsync(new() { ["target"] = "127.0.0.1", ["ports"] = "80", ["timeout_ms"] = "1000" }));
        foreach (var r in await Task.WhenAll(tasks))
            Assert.True(r.Success);
    }

    private static PortScanTool CreateTool() =>
        new(Microsoft.Extensions.Logging.Abstractions.NullLogger<PortScanTool>.Instance);
}
