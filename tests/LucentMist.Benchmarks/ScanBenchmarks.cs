using BenchmarkDotNet.Attributes;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Benchmarks;

[ShortRunJob]
[MemoryDiagnoser]
public class ScanBenchmarks
{
    private readonly PingScanTool _ping = new(NullLogger<PingScanTool>.Instance);
    private readonly PortScanTool _port = new(NullLogger<PortScanTool>.Instance);
    private readonly UdpScanTool _udp = new(NullLogger<UdpScanTool>.Instance);

    [Benchmark] public Task Ping_24_Concurrency50() => Ping(50);
    [Benchmark] public Task Ping_24_Concurrency100() => Ping(100);
    [Benchmark] public Task Ping_24_Concurrency200() => Ping(200);

    [Benchmark] public Task Port_1000_Concurrency10() => Port(10);
    [Benchmark] public Task Port_1000_Concurrency50() => Port(50);
    [Benchmark] public Task Port_1000_Concurrency100() => Port(100);

    [Benchmark] public Task Udp_6Port_Concurrency1() => Udp(1);
    [Benchmark] public Task Udp_6Port_Concurrency5() => Udp(5);
    [Benchmark] public Task Udp_6Port_Concurrency10() => Udp(10);

    private Task Ping(int concurrency) => _ping.ExecuteAsync(new ToolArguments
    {
        ["target"] = "127.0.0.0/24",
        ["timeout_ms"] = "300",
        ["concurrency"] = concurrency.ToString(),
    });

    private Task Port(int concurrency) => _port.ExecuteAsync(new ToolArguments
    {
        ["target"] = "127.0.0.1",
        ["ports"] = "1-1000",
        ["timeout_ms"] = "100",
        ["concurrency"] = concurrency.ToString(),
    });

    private Task Udp(int concurrency) => _udp.ExecuteAsync(new ToolArguments
    {
        ["target"] = "127.0.0.1",
        ["ports"] = "53,123,161,500,514,1900",
        ["timeout_ms"] = "400",
        ["concurrency"] = concurrency.ToString(),
    });
}
