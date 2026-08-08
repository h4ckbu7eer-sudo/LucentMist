using LucentMist.Scanning;

namespace LucentMist.Scanning.Tests;

public class ScanCoordinatorTests
{
    [Fact]
    public async Task StartAsync_Enqueues_And_Persists()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"lmist-coord-{Guid.NewGuid():N}.db");
        try
        {
            var store = new ScanStore(dbPath);
            var coordinator = new ScanCoordinator(store);

            var taskId = await coordinator.StartAsync("10.0.0.1", "tcp", "80,443");

            Assert.False(string.IsNullOrWhiteSpace(taskId));
            var rec = await store.GetAsync(taskId);
            Assert.NotNull(rec);
            Assert.Equal("pending", rec!.Status);

            Assert.True(await coordinator.Reader.WaitToReadAsync());
            Assert.True(coordinator.Reader.TryRead(out var job));
            Assert.Equal(taskId, job!.TaskId);
            Assert.Equal("tcp", job.ScanType);
            Assert.Equal("80,443", job.Ports);
        }
        finally
        {
            if (File.Exists(dbPath)) File.Delete(dbPath);
        }
    }
}
