using System.Security.Cryptography;
using System.Text;

namespace LucentMist.Scanning.Monitoring;

public sealed class NetworkMonitor(MonitorStore store, Func<CancellationToken, Task<NetworkSnapshot>> scan,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public async Task RunAsync(MonitorScope scope, TimeSpan interval, int? cycles,
        Func<MonitorUpdate, Task> publish, CancellationToken ct)
    {
        if (interval < TimeSpan.FromMinutes(1) || interval > TimeSpan.FromDays(1)) throw new ArgumentOutOfRangeException(nameof(interval));
        if (cycles is <= 0) throw new ArgumentOutOfRangeException(nameof(cycles));
        for (var round = 0; !cycles.HasValue || round < cycles.Value; round++)
        {
            ct.ThrowIfCancellationRequested();
            NetworkSnapshot snapshot;
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromMinutes(3));
            try { snapshot = await scan(budget.Token); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or System.Net.Sockets.SocketException or System.Text.Json.JsonException)
            { snapshot = new(false, [], "扫描未完成（超时/读取失败），请检查网络与日志。"); }
            var update = store.Apply(scope, snapshot, DateTimeOffset.UtcNow);
            await publish(update);
            if (cycles.HasValue && round + 1 >= cycles.Value) break;
            await (delay ?? Task.Delay)(interval, ct); // Fixed delay: scans never overlap or queue up.
        }
    }

    public static FileStream AcquireLease(string dbPath, MonitorScope scope)
    {
        var path = Path.GetFullPath(dbPath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scope.Id)))[..16];
        return new FileStream(path + ".monitor-" + key + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
}
