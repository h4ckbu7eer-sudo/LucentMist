using System.Buffers.Binary;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class DnsSecurityProbeTests
{
    [Fact]
    public void RecursionQuery_IsSmallAQueryNotAmplificationPayload()
    {
        var query = DnsSecurityProbe.BuildQuery("example.com", 1, 1, recursionDesired: true);
        Assert.True(query.Length < 64);
        Assert.Equal(0x0100, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2)));
        Assert.Equal(1, query[^4] << 8 | query[^3]);
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
