using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class DiscoveryEnrichmentTests
{
    [Fact]
    public void OuiDatabase_LoadsQuotedIeeeCsvAndHandlesRandomMac()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllLines(path,
            [
                "Registry,Assignment,Organization Name,Organization Address",
                "MA-L,A1B2C3,\"Example Devices, Inc.\",Somewhere",
            ]);
            var database = new OuiDatabase(path);
            Assert.Equal("Example Devices, Inc.", database.Lookup("A1:B2:C3:00:11:22"));
            Assert.Contains("随机 MAC", database.Lookup("02:00:00:00:00:01"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void OuiDatabase_LoadsInstalledNmapPrefixFormat()
    {
        var database = new OuiDatabase();
        database.LoadNmapPrefixes(["A8CDEF Example Network Devices"]);

        Assert.Equal("Example Network Devices", database.Lookup("A8:CD:EF:01:02:03"));
    }

    [Fact]
    public void MdnsQuery_IsReversePtrWithUnicastResponseBit()
    {
        var packet = MdnsProbe.BuildReversePtrQuery(IPAddress.Parse("192.168.2.9"));
        var text = Encoding.ASCII.GetString(packet);
        Assert.Contains("in-addr", text);
        Assert.Equal(12, packet[^4] << 8 | packet[^3]);
        Assert.Equal(0x8001, packet[^2] << 8 | packet[^1]);
    }

    [Fact]
    public async Task PingResult_IncludesVendorNameAndHonestModelBoundary()
    {
        var tool = new PingScanTool(
            NullLogger<PingScanTool>.Instance,
            (_, _, _) => Task.FromResult(IPStatus.Success),
            (_, _, _) => Task.FromResult(false),
            (_, _) => Task.FromResult<IReadOnlyDictionary<string, string>>(
                new Dictionary<string, string> { ["192.168.2.9"] = "00:0C:29:AA:BB:CC" }),
            (_, _) => Task.FromResult<string?>("office-pc.local"),
            new OuiDatabase());
        var result = await tool.ExecuteAsync(new() { ["target"] = "192.168.2.9" });
        Assert.True(result.Success, result.Error);
        using var document = JsonDocument.Parse(result.Data);
        var device = document.RootElement.GetProperty("deviceDetails")[0];
        Assert.Contains("VMware", device.GetProperty("vendor").GetString());
        Assert.Equal("office-pc.local", device.GetProperty("name").GetString());
        Assert.Contains("需服务指纹", device.GetProperty("model").GetString());
    }
}
