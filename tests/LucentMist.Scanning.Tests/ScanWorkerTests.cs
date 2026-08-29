using System.Diagnostics;
using System.Threading.Channels;
using LucentMist.Scanning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit.Abstractions;

namespace LucentMist.Scanning.Tests;

public sealed class ScanWorkerTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(), $"lmist-worker-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [Fact]
    public async Task CompletedPublishCanceledAfterPersistence_RemainsCompleted()
    {
        var store = new ScanStore(_dbPath);
        var coordinator = new ScanCoordinator(store);
        var worker = new ScanWorker(
            coordinator,
            store,
            new CancelCompletedPublisher(),
            new LoggerFactoryProvider(),
            NullLogger<ScanWorker>.Instance);
        var record = await store.CreateAsync("192.0.2.1", "tcp", "443");
        await store.MarkRunningAsync(record.Id);

        await worker.PersistCompletedAndPublishAsync(record.Id, 1, "{\"openPorts\":[443]}");

        var completed = await store.GetAsync(record.Id);
        Assert.Equal("completed", completed!.Status);
        Assert.Equal("{\"openPorts\":[443]}", completed.ResultJson);
        Assert.Null(completed.ErrorMessage);
    }

    [Fact]
    public async Task BoundedDispatcher_FastTcpIsNotBlockedBySlowPing()
    {
        var channel = Channel.CreateUnbounded<ScanJob>();
        await channel.Writer.WriteAsync(new ScanJob("slow", "192.0.2.0/24", "ping", ""));
        await channel.Writer.WriteAsync(new ScanJob("fast", "192.0.2.1", "tcp", "443"));
        channel.Writer.Complete();

        var timer = Stopwatch.StartNew();
        var fastCompleted = new TaskCompletionSource<TimeSpan>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var active = 0;
        var maximumActive = 0;

        async Task ExecuteAsync(ScanJob job, CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref active);
            UpdateMaximum(ref maximumActive, current);
            try
            {
                if (job.ScanType == "ping")
                    await Task.Delay(500, cancellationToken);
                else
                {
                    await Task.Delay(20, cancellationToken);
                    fastCompleted.TrySetResult(timer.Elapsed);
                }
            }
            finally
            {
                Interlocked.Decrement(ref active);
            }
        }

        var dispatcher = BoundedScanDispatcher.RunAsync(
            channel.Reader,
            ExecuteAsync,
            maxConcurrency: 2,
            CancellationToken.None);
        var fastElapsed = await fastCompleted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await dispatcher;
        timer.Stop();

        output.WriteLine(
            $"fast TCP completed at {fastElapsed.TotalMilliseconds:F0}ms; " +
            $"slow ping/whole batch completed at {timer.Elapsed.TotalMilliseconds:F0}ms; " +
            $"max-active={maximumActive}");

        Assert.True(
            fastElapsed < TimeSpan.FromMilliseconds(250),
            $"Fast TCP was head-of-line blocked for {fastElapsed.TotalMilliseconds:F0}ms");
        Assert.True(timer.Elapsed >= TimeSpan.FromMilliseconds(450));
        Assert.Equal(2, maximumActive);
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

    private sealed class CancelCompletedPublisher : IScanProgressPublisher
    {
        public Task PublishAsync(ScanProgressEvent evt, CancellationToken ct = default) =>
            evt.Status == "completed"
                ? Task.FromException(new OperationCanceledException(ct))
                : Task.CompletedTask;
    }

    private sealed class LoggerFactoryProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) =>
            serviceType == typeof(ILoggerFactory) ? NullLoggerFactory.Instance : null;
    }
}
