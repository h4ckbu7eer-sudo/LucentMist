using LucentMist.Scanning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Scanning.Tests;

public sealed class ScanWorkerTests : IDisposable
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
