extern alias LucentMistWeb;

using System.Collections.Concurrent;
using LucentMist.Scanning;
using Microsoft.AspNetCore.Components;
using Microsoft.Data.Sqlite;
using ScanTaskClient = LucentMistWeb::LucentMist.Web.ScanTaskClient;

namespace LucentMist.API.Tests;

public sealed class ScanTaskClientTests
{
    [Fact]
    public async Task TransientSqliteBusy_RetriesWithoutReportingScanFailure()
    {
        var coordinator = new QueueCoordinator("task-1");
        var reader = new BusyThenCompletedReader(new ScanTaskRecord
        {
            Id = "task-1",
            Target = "127.0.0.1",
            ScanType = "ping",
            Status = "completed",
            ResultJson = "{}"
        });
        await using var client = CreateClient(coordinator, reader);
        var completed = new TaskCompletionSource<ScanTaskRecord>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var failureCount = 0;
        client.Completed += record => completed.TrySetResult(record);
        client.Failed += (_, _) => Interlocked.Increment(ref failureCount);

        await client.StartAsync("127.0.0.1", "ping", "");
        var result = await completed.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal("task-1", result.Id);
        Assert.Equal(0, failureCount);
        Assert.Equal("completed", client.CurrentStatus);
        Assert.Null(client.LastError);
        Assert.Null(client.MonitoringError);
        Assert.Equal(2, reader.ReadCount);
    }

    [Fact]
    public async Task ReplacedRun_CannotPublishLateResultIntoCurrentRun()
    {
        var coordinator = new QueueCoordinator("task-a", "task-b");
        var reader = new ControlledReader("task-a", "task-b");
        await using var client = CreateClient(coordinator, reader);
        var completedIds = new ConcurrentQueue<string>();
        var taskBCompleted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        client.Completed += record =>
        {
            completedIds.Enqueue(record.Id);
            if (record.Id == "task-b") taskBCompleted.TrySetResult();
        };

        Assert.Equal("task-a", await client.StartAsync("10.0.0.1", "ping", ""));
        await reader.WaitUntilReadAsync("task-a");
        Assert.Equal("task-b", await client.StartAsync("10.0.0.2", "tcp", "443"));
        await reader.WaitUntilReadAsync("task-b");

        reader.Complete("task-a", Completed("task-a", "10.0.0.1"));
        await Task.Delay(25);

        Assert.Empty(completedIds);
        Assert.Equal("task-b", client.CurrentTaskId);
        Assert.Equal("pending", client.CurrentStatus);

        reader.Complete("task-b", Completed("task-b", "10.0.0.2"));
        await taskBCompleted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(["task-b"], completedIds.ToArray());
        Assert.Equal("completed", client.CurrentStatus);
    }

    private static ScanTaskClient CreateClient(
        IScanCoordinator coordinator,
        IScanTaskReader reader) =>
        new(
            coordinator,
            reader,
            new TestNavigationManager(),
            (_, token) => Task.Delay(1, token),
            enableSignalR: false);

    private static ScanTaskRecord Completed(string id, string target) => new()
    {
        Id = id,
        Target = target,
        ScanType = "ping",
        Status = "completed",
        ResultJson = "{}"
    };

    private sealed class QueueCoordinator(params string[] ids) : IScanCoordinator
    {
        private readonly Queue<string> _ids = new(ids);

        public Task<string> StartAsync(
            string target,
            string scanType = "ping",
            string ports = "",
            CancellationToken ct = default) =>
            Task.FromResult(_ids.Dequeue());
    }

    private sealed class BusyThenCompletedReader(ScanTaskRecord completed) : IScanTaskReader
    {
        private int _readCount;

        public int ReadCount => Volatile.Read(ref _readCount);

        public Task<ScanTaskRecord?> GetAsync(string id)
        {
            if (Interlocked.Increment(ref _readCount) == 1)
                return Task.FromException<ScanTaskRecord?>(
                    new SqliteException("database is busy", 5));
            return Task.FromResult<ScanTaskRecord?>(completed);
        }
    }

    private sealed class ControlledReader : IScanTaskReader
    {
        private readonly ConcurrentDictionary<string, TaskCompletionSource<ScanTaskRecord?>> _results;
        private readonly ConcurrentDictionary<string, TaskCompletionSource> _reads;

        public ControlledReader(params string[] ids)
        {
            _results = new(ids.Select(id => new KeyValuePair<string, TaskCompletionSource<ScanTaskRecord?>>(
                id,
                new(TaskCreationOptions.RunContinuationsAsynchronously))));
            _reads = new(ids.Select(id => new KeyValuePair<string, TaskCompletionSource>(
                id,
                new(TaskCreationOptions.RunContinuationsAsynchronously))));
        }

        public Task<ScanTaskRecord?> GetAsync(string id)
        {
            _reads[id].TrySetResult();
            return _results[id].Task;
        }

        public Task WaitUntilReadAsync(string id) =>
            _reads[id].Task.WaitAsync(TimeSpan.FromSeconds(2));

        public void Complete(string id, ScanTaskRecord record) =>
            _results[id].TrySetResult(record);
    }

    private sealed class TestNavigationManager : NavigationManager
    {
        public TestNavigationManager() =>
            Initialize("http://localhost/", "http://localhost/");

        protected override void NavigateToCore(string uri, bool forceLoad)
        {
        }
    }
}
