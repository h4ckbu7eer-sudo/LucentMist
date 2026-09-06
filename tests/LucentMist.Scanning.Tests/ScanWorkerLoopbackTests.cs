using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Scanning.Tests;

public class ScanWorkerLoopbackTests
{
    [Fact]
    public async Task RealQueuedToolsPreserveTcpEvidenceAndUdpUncertaintyInSqlite()
    {
        var path = Path.Combine(Path.GetTempPath(), $"lmist-queue-{Guid.NewGuid():N}.db");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var services = new TestServices();
        var store = new ScanStore(path);
        var coordinator = new ScanCoordinator(store);
        using var worker = new ScanWorker(coordinator, store, new NullScanProgressPublisher(), services, NullLogger<ScanWorker>.Instance);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await worker.StartAsync(deadline.Token);
            var tcp = await coordinator.StartAsync("127.0.0.1", "tcp", port.ToString(), deadline.Token);
            var udp = await coordinator.StartAsync("127.0.0.1", "udp", "514", deadline.Token);
            using var tcpResult = JsonDocument.Parse((await Wait(tcp)).ResultJson!);
            Assert.Contains(tcpResult.RootElement.GetProperty("openPorts").EnumerateArray(), p => p.GetInt32() == port);
            using var udpResult = JsonDocument.Parse((await Wait(udp)).ResultJson!);
            Assert.Equal("unprobeable", udpResult.RootElement.GetProperty("ports")[0].GetProperty("state").GetString());
            Assert.Equal(0, udpResult.RootElement.GetProperty("openPorts").GetArrayLength());
            Assert.Contains("无法", udpResult.RootElement.GetProperty("ports")[0].GetProperty("detail").GetString());
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
            foreach (var suffix in new[] { "", "-wal", "-shm" })
                if (File.Exists(path + suffix)) File.Delete(path + suffix);
        }

        async Task<ScanTaskRecord> Wait(string id)
        {
            while (true)
            {
                var record = await store.GetAsync(id, deadline.Token);
                if (record?.Status is "completed" or "failed")
                {
                    Assert.Equal("completed", record.Status);
                    return record;
                }
                await Task.Delay(20, deadline.Token);
            }
        }
    }

    private sealed class TestServices : IServiceProvider
    {
        public object? GetService(Type type) => type == typeof(ILoggerFactory) ? NullLoggerFactory.Instance : null;
    }
}
