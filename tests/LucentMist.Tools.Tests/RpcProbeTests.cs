using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class RpcProbeTests
{
    private static byte[] AcceptedReply()
    {
        var reply = new byte[56];
        reply[0] = 5; reply[2] = 12; reply[3] = 3; reply[4] = 0x10;
        BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(8), 56);
        BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(12), 1);
        reply[28] = 1;
        new Guid("8a885d04-1ceb-11c9-9fe8-08002b104860").ToByteArray().CopyTo(reply, 36);
        BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(52), 2);
        return reply;
    }

    [Fact]
    public void BindTargetsEndpointMapperAndRejectsUnrelatedOrRefusedReplies()
    {
        var bind = RpcProbe.BuildBind();
        Assert.Equal(72, bind.Length);
        Assert.Equal(new Guid("e1af8308-5d1f-11c9-91a4-08002b14a0fa"), new Guid(bind.AsSpan(32, 16)));
        Assert.True(RpcProbe.IsAcceptedBind(AcceptedReply()));
        foreach (var offset in new[] { 0, 2, 4, 8, 12, 28, 32, 36, 52 })
        {
            var reply = AcceptedReply();
            reply[offset] ^= 1;
            Assert.False(RpcProbe.IsAcceptedBind(reply));
        }
        Assert.False(RpcProbe.IsAcceptedBind(AcceptedReply()[..40]));
    }

    [Fact]
    public async Task FragmentedTcpAckProducesProtocolEvidenceNotWindowsVersion()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var probe = RpcProbe.ProbeAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, 4000, timeout.Token);
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        using var stream = client.GetStream();
        var request = new byte[72];
        await stream.ReadExactlyAsync(request, timeout.Token);
        Assert.Equal(RpcProbe.BuildBind(), request);
        foreach (var value in AcceptedReply()) await stream.WriteAsync(new byte[] { value }, timeout.Token);
        var banner = await probe;
        var fingerprint = ServiceFingerprint.FromBanner(banner);
        Assert.Contains("Bind ACK", banner);
        Assert.Equal("dce-rpc", fingerprint?.ProductKey);
        Assert.Null(fingerprint?.Cpe);
        Assert.Null(fingerprint?.Version);
        Assert.DoesNotContain("Windows", banner);
    }
}
