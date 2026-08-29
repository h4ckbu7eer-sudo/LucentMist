using System.Threading.Channels;

namespace LucentMist.Scanning;

internal static class BoundedScanDispatcher
{
    internal static async Task RunAsync(
        ChannelReader<ScanJob> reader,
        Func<ScanJob, CancellationToken, Task> executeAsync,
        int maxConcurrency,
        CancellationToken cancellationToken)
    {
        var degree = Math.Clamp(maxConcurrency, 1, 3);
        var active = new HashSet<Task>();

        try
        {
            while (await reader.WaitToReadAsync(cancellationToken))
            {
                while (active.Count >= degree)
                    await AwaitOneAsync(active);

                while (active.Count < degree && reader.TryRead(out var job))
                    active.Add(executeAsync(job, cancellationToken));
            }

            await Task.WhenAll(active);
        }
        finally
        {
            if (active.Count > 0)
            {
                try
                {
                    await Task.WhenAll(active);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                }
            }
        }
    }

    private static async Task AwaitOneAsync(HashSet<Task> active)
    {
        var completed = await Task.WhenAny(active);
        active.Remove(completed);
        await completed;
    }
}
