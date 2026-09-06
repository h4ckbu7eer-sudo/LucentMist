using System.Net;
using System.Net.Sockets;
using LucentMist.Tools.Discovery;

namespace LucentMist.Tools.Tests;

public sealed class AndroidDiscoveryTests
{
    [Theory]
    [InlineData("_android._tcp.local")]
    [InlineData("_adb._tcp.local")]
    [InlineData("_adb-tls-connect._tcp.local")]
    [InlineData("_adb-tls-pairing._tcp.local")]
    public async Task DirectedMdnsActuallyQueriesAndroidTypes_AndFollowsLinkedInstance(string type)
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var instance = "phone." + type;
        var serving = Task.Run(async () =>
        {
            while (true)
            {
                var request = await udp.ReceiveAsync(timeout.Token);
                var offset = 12;
                Assert.True(DnsRecords.ReadName(request.Buffer, ref offset, out var name));
                if (name != type) continue;
                var data = DnsSecurityProbe.BuildQuery(instance, 12, 1, false)[12..^4];
                var response = request.Buffer.ToArray(); response[2] = 0x84; response[7] = 1;
                byte[] packet = [.. response, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 30, 0, (byte)data.Length, .. data];
                await udp.SendAsync(packet, request.RemoteEndPoint, timeout.Token);
                break;
            }
            while (true)
            {
                var request = await udp.ReceiveAsync(timeout.Token);
                var offset = 12;
                Assert.True(DnsRecords.ReadName(request.Buffer, ref offset, out var name));
                if (name == instance) return name;
            }
        }, timeout.Token);
        var identity = await MdnsProbe.ProbeAsync("127.0.0.1", ((IPEndPoint)udp.Client.LocalEndPoint!).Port, timeout.Token);
        Assert.Equal(instance, await serving);
        Assert.Contains(type, identity.Services!);
        Assert.Equal("response_observed", identity.Status);
        Assert.Null(identity.Model); // ADB alone is not a phone model.
        Assert.InRange(identity.Queries, 8, MdnsProbe.MaxQueries);
    }

    [Fact]
    public void RandomMacStillAcceptsLinkedModelEvidence_ButNoResponseDoesNotInventADevice()
    {
        const string type = "_adb-tls-connect._tcp.local";
        var identity = MdnsProbe.Identify([
            new(type, 12, 1, "phone." + type, []),
            new("phone." + type, 16, 1, null, ["model=Test-Phone"]),
            new("phone." + type, 33, 1, "android-99.local", []),
            new("unrelated.local", 16, 1, null, ["model=Unrelated"]),
        ], "reverse", 10);
        var device = DeviceDiscovery.BuildRemoteIdentity("192.168.77.2", "02:11:22:33:44:55", identity, null);
        Assert.Equal("android-99.local", device.Name);
        Assert.Equal("Test-Phone", device.Model);
        Assert.Contains(type, device.IdentityEvidence);
        Assert.Contains("随机 MAC", device.Vendor);
        var absent = DeviceDiscovery.BuildRemoteIdentity("192.168.77.2", "02:11:22:33:44:55", MdnsProbe.Identify([], "reverse", 8), null);
        Assert.StartsWith("未知", absent.Model);
        Assert.Contains("无响应不代表未广播", absent.IdentityEvidence);
        Assert.Empty(absent.MdnsServices);
    }
}
