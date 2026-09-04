using System.Buffers.Binary;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class DnsSecurityProbeTests
{
    [Theory]
    [InlineData(2000, 2000)]
    [InlineData(50, 100)]
    [InlineData(8000, 5000)]
    public void UdpReceivesFullBoundedBudgetBeforeTcpFallback(int requested, int expected)
    {
        Assert.Equal(expected, DnsSecurityProbe.UdpTimeoutBudget(requested));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("unknow")]
    [InlineData("hidden")]
    [InlineData("not disclosed")]
    public void PlaceholderVersion_IsNotPresentedAsSoftwareVersion(string value)
    {
        Assert.Null(DnsSecurityProbe.NormalizeVersion(value));
        Assert.Equal("BIND 9.18.1", DnsSecurityProbe.NormalizeVersion("BIND 9.18.1"));
    }

    private static DnsSecurityResult Snapshot(bool available) => new(null, "版本未知", available,
        available ? "对当前扫描源开放递归" : "状态未知", 29, 0, 0);

    [Fact]
    public async Task ServiceIdentifyAndVulnerabilityToolUseTheSameAnalysisSnapshot()
    {
        using var scope = DnsSecurityProbe.BeginAnalysisScope();
        await DnsSecurityProbe.SnapshotAsync("127.0.0.1", () => Task.FromResult(Snapshot(true)));
        var service = await new ServiceIdentifyTool(NullLogger<ServiceIdentifyTool>.Instance)
            .ExecuteAsync(new() { ["target"] = "127.0.0.1", ["port"] = "53" });
        var vulnerability = await new VulnerabilityScanTool((_, _, _, _) => Task.FromResult(new CveApiClient.QueryReport([], [])))
            .ExecuteAsync(new() { ["target"] = "127.0.0.1", ["open_ports"] = "53" });
        Assert.True(service.Success, service.Error);
        Assert.True(vulnerability.Success, vulnerability.Error);
        using var serviceJson = JsonDocument.Parse(service.Data);
        using var vulnerabilityJson = JsonDocument.Parse(vulnerability.Data);
        Assert.Equal(serviceJson.RootElement.GetProperty("dnsSecurity").GetRawText(),
            vulnerabilityJson.RootElement.GetProperty("dnsSecurity").GetRawText());
    }

    [Fact]
    public async Task OneAnalysisSharesSingleDnsEvidence_NewAnalysisReprobes()
    {
        var count = 0;
        Task<DnsSecurityResult> Probe() => Task.FromResult(Snapshot(Interlocked.Increment(ref count) == 1));
        DnsSecurityResult first;
        using (DnsSecurityProbe.BeginAnalysisScope())
        {
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                DnsSecurityProbe.SnapshotAsync("192.168.99.1", Probe)));
            first = results[0];
            Assert.All(results, item => Assert.Same(first, item));
            Assert.Equal(1, count);
        }
        using (DnsSecurityProbe.BeginAnalysisScope())
        {
            var next = await DnsSecurityProbe.SnapshotAsync("192.168.99.1", Probe);
            Assert.NotEqual(first.EvidenceId, next.EvidenceId);
            Assert.False(next.RecursionAvailable);
        }
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task ConcurrentAnalysesDoNotShareDnsEvidence()
    {
        async Task<DnsSecurityResult> Run(bool available)
        {
            using var scope = DnsSecurityProbe.BeginAnalysisScope();
            await Task.Yield();
            return await DnsSecurityProbe.SnapshotAsync("192.168.99.1", () => Task.FromResult(Snapshot(available)));
        }
        var results = await Task.WhenAll(Run(true), Run(false));
        Assert.True(results[0].RecursionAvailable);
        Assert.False(results[1].RecursionAvailable);
        Assert.NotEqual(results[0].EvidenceId, results[1].EvidenceId);
    }

    [Fact]
    public void UnrelatedDnsResponseIsNotAcceptedAsRecursionEvidence()
    {
        var query = DnsSecurityProbe.BuildQuery("example.com", 1, 1, true);
        var reply = query.ToArray();
        reply[2] |= 0x80;
        Assert.True(DnsSecurityProbe.IsResponseTo(query, reply));
        reply[1] ^= 1;
        Assert.False(DnsSecurityProbe.IsResponseTo(query, reply));
        Assert.False(DnsSecurityProbe.IsResponseTo(query, query));
        Assert.False(DnsSecurityProbe.IsResponseTo(query, []));
    }

    [Fact]
    public void RecursionQuery_IsSmallAQueryNotAmplificationPayload()
    {
        var query = DnsSecurityProbe.BuildQuery("example.com", 1, 1, recursionDesired: true);
        Assert.True(query.Length < 64);
        Assert.Equal(0x0100, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2)));
        Assert.Equal(1, query[^4] << 8 | query[^3]);
    }

    [Fact]
    public async Task RecursionProbeRunsBeforeIdentityBurst_AndRetriesOneMissingResponse()
    {
        var calls = new List<bool>();
        var recursionCalls = 0;
        var result = await DnsSecurityProbe.ProbeWithSenderAsync("192.0.2.53", query =>
        {
            var recursionDesired = (BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2)) & 0x0100) != 0;
            calls.Add(recursionDesired);
            if (!recursionDesired || ++recursionCalls == 1) return Task.FromResult<byte[]?>(null);

            var response = query.ToArray();
            response[2] |= 0x80;
            response[3] |= 0x80;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), 1);
            return Task.FromResult<byte[]?>(response);
        });

        Assert.Equal([true, true], calls.Take(2));
        Assert.True(result.RecursionAvailable);
        Assert.Equal("observed", result.RecursionStatus);
        Assert.Equal(2, result.RecursionProbeAttempts);
    }

    [Fact]
    public async Task ServiceIdentify_DnsIncludesVersionAndRecursionAssessment()
    {
        var tool = new ServiceIdentifyTool(
            NullLogger<ServiceIdentifyTool>.Instance,
            (_, _, _) => Task.FromResult(new DnsSecurityResult(
                "BIND 9.18", "服务器公开了 DNS 软件版本", true,
                "对当前扫描源开放递归；若该服务可从公网访问，可能被用于 DNS 反射/放大攻击",
                29, 96, 3.31)));
        var result = await tool.ExecuteAsync(new() { ["target"] = "127.0.0.1", ["port"] = "53" });
        Assert.True(result.Success, result.Error);
        using var document = JsonDocument.Parse(result.Data);
        var dns = document.RootElement.GetProperty("dnsSecurity");
        Assert.Equal("BIND 9.18", dns.GetProperty("version").GetString());
        Assert.True(dns.GetProperty("recursionAvailable").GetBoolean());
        Assert.Contains("放大攻击", dns.GetProperty("recursionAssessment").GetString());
    }
}
