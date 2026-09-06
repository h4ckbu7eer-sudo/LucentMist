using System.Text.Json;
using LucentMist.Tools;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Scanning.Tests;

public sealed class ScanWorkerResultTests : IDisposable
{
    private readonly string _db = Path.Combine(Path.GetTempPath(), $"lmist-result-{Guid.NewGuid():N}.db");
    private static readonly ScanJob Job = new("test", "127.0.0.1", "ping", "");
    private ScanWorker Worker(IScanProgressPublisher? publisher = null)
    {
        var store = new ScanStore(_db);
        return new(new(store), store, publisher ?? new NullScanProgressPublisher(), new Services(), NullLogger<ScanWorker>.Instance);
    }
    public void Dispose() { foreach (var suffix in new[] { "", "-wal", "-shm" }) if (File.Exists(_db + suffix)) File.Delete(_db + suffix); }
    private static ToolResult Ok(string data) => ToolResult.Ok(data, TimeSpan.Zero);

    [Theory]
    [InlineData("{broken")]
    [InlineData("{\"alive\":1}")]
    public async Task InvalidDiscoveryCannotBecomeCompletedWithEmptyEvidence(string json)
    {
        var outcome = await Worker().RunPingAsync(Job, DateTime.UtcNow, default,
            new Fake((_, _) => Task.FromResult(Ok(json))));
        Assert.NotNull(outcome.Error);
        Assert.Null(outcome.ResultJson);
    }

    [Fact]
    public async Task CancellationDuringPortEnrichmentCannotReturnCompleted()
    {
        using var stop = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Worker().RunPingAsync(Job, DateTime.UtcNow, stop.Token,
            new Fake((_, _) => Task.FromResult(Ok("""{"alive":1,"devices":["127.0.0.1"]}"""))),
            new Fake((_, ct) => { stop.Cancel(); ct.ThrowIfCancellationRequested(); return Task.FromResult(Ok("{}")); })));
    }

    [Fact]
    public async Task ProgressTransportCancellationDoesNotCancelTheActualScan()
    {
        var outcome = await Worker(new CancelNotification()).RunPingAsync(Job, DateTime.UtcNow, default,
            new Fake((_, _) => Task.FromResult(Ok("""{"alive":0,"devices":[],"deviceDetails":[]}"""))));
        Assert.Null(outcome.Error);
    }

    [Fact]
    public void UdpResultKeepsIndeterminateAndUnprobeableStates()
    {
        var outcome = ScanWorker.BuildPortOutcome(Job, DateTime.UtcNow,
            """{"totalScanned":2,"openPorts":[],"ports":[{"port":123,"state":"open|filtered"},{"port":514,"state":"unprobeable"}],"interpretation":"not closed"}""", "udp");
        using var result = JsonDocument.Parse(outcome.ResultJson!);
        Assert.Equal("open|filtered", result.RootElement.GetProperty("ports")[0].GetProperty("state").GetString());
        Assert.Equal("not closed", result.RootElement.GetProperty("interpretation").GetString());
    }

    [Fact]
    public void MissingPortResultsCannotBeAcceptedAsNoOpenPorts()
    {
        var outcome = ScanWorker.BuildPortOutcome(Job, DateTime.UtcNow, "{}", "tcp");
        Assert.NotNull(outcome.Error);
    }

    [Fact]
    public async Task DiscoveryKeepsDeviceMetadataAndMarksFailedVersusUnscannedEnrichment()
    {
        var outcome = await Worker().RunPingAsync(Job, DateTime.UtcNow, default,
            new Fake((_, _) => Task.FromResult(Ok("""{"alive":6,"devices":["127.0.0.1","127.0.0.2","127.0.0.3","127.0.0.4","127.0.0.5","127.0.0.6"],"deviceDetails":[{"ip":"127.0.0.1","vendor":"test-vendor"}]}"""))),
            new Fake((args, _) => Task.FromResult(args.GetOrDefault("target") == "127.0.0.1"
                ? ToolResult.Fail("port failure", TimeSpan.Zero) : Ok("""{"openPorts":[]}"""))));
        Assert.Null(outcome.Error);
        using var doc = JsonDocument.Parse(outcome.ResultJson!);
        var root = doc.RootElement;
        Assert.Equal("test-vendor", root.GetProperty("deviceDetails")[0].GetProperty("vendor").GetString());
        Assert.True(root.GetProperty("portScanFailures").TryGetProperty("127.0.0.1", out _));
        Assert.False(root.GetProperty("openPortsByIp").TryGetProperty("127.0.0.1", out _));
        Assert.Equal(0, root.GetProperty("openPortsByIp").GetProperty("127.0.0.2").GetArrayLength());
        Assert.Equal(1, root.GetProperty("portScanScope").GetProperty("notScannedDeviceCount").GetInt32());
        Assert.False(root.GetProperty("openPortsByIp").TryGetProperty("127.0.0.6", out _));
    }

    private sealed class Fake(Func<ToolArguments, CancellationToken, Task<ToolResult>> run) : ITool
    {
        public string Name => "fake";
        public string Description => "test";
        public ToolParameter[] Parameters => [];
        public Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default) => run(args, cancellationToken);
    }
    private sealed class Services : IServiceProvider
    {
        public object? GetService(Type serviceType) => serviceType == typeof(ILoggerFactory) ? NullLoggerFactory.Instance : null;
    }
    private sealed class CancelNotification : IScanProgressPublisher
    {
        public Task PublishAsync(ScanProgressEvent evt, CancellationToken ct = default) => Task.FromException(new OperationCanceledException());
    }
}
