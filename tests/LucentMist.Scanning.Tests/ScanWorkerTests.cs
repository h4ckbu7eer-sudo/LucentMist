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
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var slowStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSlow = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
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
                {
                    slowStarted.TrySetResult();
                    await releaseSlow.Task.WaitAsync(cancellationToken);
                }
                else
                {
                    await slowStarted.Task.WaitAsync(cancellationToken);
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
            deadline.Token);
        try
        {
            var fastElapsed = await fastCompleted.Task.WaitAsync(deadline.Token);
            // Prove ordering while the slow scan is still held, independently of
            // CI scheduling latency. A serial dispatcher cannot reach this point.
            Assert.False(releaseSlow.Task.IsCompleted);
            Assert.False(dispatcher.IsCompleted);
            Assert.Equal(2, maximumActive);
            output.WriteLine($"fast TCP completed before slow ping was released; elapsed={fastElapsed.TotalMilliseconds:F0}ms; max-active={maximumActive}");
        }
        finally
        {
            releaseSlow.TrySetResult();
            await dispatcher;
            timer.Stop();
        }
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
