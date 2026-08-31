using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Scanning;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class DeviceEvidenceTests
{
    [Fact]
    public async Task MdnsProductionPathFollowsServicePtrThenTxt_WithinBudget()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var names = new List<string>();
        var serving = Task.Run(async () =>
        {
            for (var i = 0; i < 4; i++)
            {
                var received = await server.ReceiveAsync(deadline.Token);
                var offset = 12;
                Assert.True(DnsRecords.ReadName(received.Buffer, ref offset, out var question));
                names.Add(question);
                byte[] packet;
                if (question == "router._http._tcp.local") packet = Txt(question, "model=Example-Router", 1);
                else
                {
                    var answerName = question switch
                    {
                        "_services._dns-sd._udp.local" => "_http._tcp.local",
                        "_http._tcp.local" => "router._http._tcp.local",
                        _ => "router.local",
                    };
                    var query = received.Buffer.ToArray();
                    query[2] = 0x80; query[7] = 1;
                    var rdata = DnsSecurityProbe.BuildQuery(answerName, 12, 1, false)[12..^4];
                    packet = [.. query, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 30, 0, (byte)rdata.Length, .. rdata];
                }
                await server.SendAsync(packet, received.RemoteEndPoint, deadline.Token);
            }
        }, deadline.Token);
        var result = await MdnsProbe.ProbeAsync("127.0.0.1", ((IPEndPoint)server.Client.LocalEndPoint!).Port, deadline.Token);
        await serving;
        Assert.Equal("router.local", result.Name);
        Assert.Equal("Example-Router", result.Model);
        Assert.Equal(4, result.Queries);
        Assert.Contains("router._http._tcp.local", names);
    }

    [Theory]
    [InlineData("version.bind", 16, 3)]
    [InlineData("hostname.bind", 16, 3)]
    [InlineData("2.168.192.in-addr.arpa", 6, 1)]
    public void DnsQueriesHaveCorrectNameTypeAndClass(string name, ushort type, ushort cls)
    {
        var query = DnsSecurityProbe.BuildQuery(name, type, cls, false);
        var offset = 12;
        Assert.True(DnsRecords.ReadName(query, ref offset, out var actual));
        Assert.Equal(name, actual);
        Assert.Equal(type, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset, 2)));
        Assert.Equal(cls, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset + 2, 2)));
        Assert.Equal(0, query[2] & 1);
    }

    [Fact]
    public void DnsRefusedAndTimeoutAreDifferent_NotFakeVersions()
    {
        var response = Txt("version.bind", "BIND 9.18.1", 3);
        Assert.Equal("BIND 9.18.1", DnsSecurityProbe.Describe("version.bind", 16, 3, response).Value);
        response[3] = 5;
        var refused = DnsSecurityProbe.Describe("version.bind", 16, 3, response);
        Assert.Equal("refused", refused.Status);
        Assert.Null(refused.Value);
        Assert.Equal("no_valid_response", DnsSecurityProbe.Describe("version.bind", 16, 3, null).Status);
    }

    [Fact]
    public void DnsDoesNotConfuseHostnameOrWrongClassWithSoftwareVersion()
    {
        Assert.Null(DnsSecurityProbe.Describe("version.bind", 16, 3, Txt("hostname.bind", "router.local", 3)).Value);
        Assert.Null(DnsSecurityProbe.Describe("version.bind", 16, 3, Txt("version.bind", "BIND 9.18.1", 1)).Value);
    }

    [Fact]
    public void DnsReplyQuestionIsCaseInsensitive_ButTypeAndTransactionMustMatch()
    {
        var query = DnsSecurityProbe.BuildQuery("version.bind", 16, 3, false);
        var response = Txt("VERSION.BIND", "BIND 9.18.1", 3);
        Assert.True(DnsSecurityProbe.IsResponseTo(query, response));
        response[0] ^= 1;
        Assert.False(DnsSecurityProbe.IsResponseTo(query, response));
    }

    [Fact]
    public void DnsMalformedTxtAndPointerCyclesAreRejected()
    {
        var packet = Txt("version.bind", "version", 3);
        packet[^8] = 250;
        Assert.Empty(DnsRecords.Read(packet));
        var loop = new byte[] { 0xc0, 0x00 };
        var offset = 0;
        Assert.False(DnsRecords.ReadName(loop, ref offset, out _));
    }

    [Fact]
    public void MdnsModelRequiresLinkedServicePtrAndTxt_NotAnUnrelatedRecord()
    {
        DnsRecords.Record[] records =
        [
            new("_services._dns-sd._udp.local", 12, 1, "_http._tcp.local", []),
            new("_http._tcp.local", 12, 1, "router._http._tcp.local", []),
            new("router._http._tcp.local", 16, 1, null, ["model=Example-Router"]),
            new("router._http._tcp.local", 33, 1, "router.local", []),
            new("unrelated.local", 16, 1, null, ["model=Wrong-Device"]),
        ];
        var identity = MdnsProbe.Identify(records, "1.2.168.192.in-addr.arpa", 4);
        Assert.Equal("Example-Router", identity.Model);
        Assert.Equal("router.local", identity.Name);
        Assert.Null(MdnsProbe.Identify(records.Skip(1), "1.2.168.192.in-addr.arpa", 4).Model);
        Assert.Equal("no_valid_unicast_response", MdnsProbe.Identify([], "reverse", 2).Status);
    }

    private static byte[] Txt(string name, string text, ushort cls)
    {
        var query = DnsSecurityProbe.BuildQuery(name, 16, cls, false);
        query[2] = 0x80; query[7] = 1;
        var value = Encoding.UTF8.GetBytes(text);
        return [.. query, 0xc0, 0x0c, 0, 16, (byte)(cls >> 8), (byte)cls, 0, 0, 0, 30, 0, (byte)(value.Length + 1), (byte)value.Length, .. value];
    }
}
