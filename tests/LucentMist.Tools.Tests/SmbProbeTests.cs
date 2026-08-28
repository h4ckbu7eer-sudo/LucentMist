using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class SmbProbeTests
{
    [Fact]
    public void ParseNegotiateResponse_Smb1ReadsDialectIndexAtOffset37()
    {
        var response = CreateSmb1Response(dialectIndex: 4, length: 74);
        BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(72), 0x0311);

        var dialect = SmbProbe.ParseNegotiateResponse(response);

        Assert.Equal("SMBv1 (NT LM 0.12)", dialect);
    }

    [Theory]
    [InlineData(0x0202, "SMBv2.0.2")]
    [InlineData(0x0210, "SMBv2.1")]
    [InlineData(0x0300, "SMBv3.0")]
    [InlineData(0x0302, "SMBv3.0.2")]
    [InlineData(0x0311, "SMBv3.1.1")]
    public void ParseNegotiateResponse_Smb2ReadsDialectRevisionAtOffset72(
        int dialectRevision,
        string expected)
    {
        var response = CreateSmb2Response((ushort)dialectRevision);

        Assert.Equal(expected, SmbProbe.ParseNegotiateResponse(response));
    }

    [Fact]
    public void ParseNegotiateResponse_DoesNotReadSmb2StructureSizeAsDialect()
    {
        var response = CreateSmb2Response(0x0311);
        response[68] = 0x11;
        response[69] = 0x03;

        Assert.Null(SmbProbe.ParseNegotiateResponse(response));
    }

    [Fact]
    public void Smb2NegotiatePacket_HasConsistentDirectTcpLengthAndRequiredContext()
    {
        var packet = SmbProbe.Smb2NegotiatePacket;
        var declaredLength = packet[1] << 16 | packet[2] << 8 | packet[3];

        Assert.Equal(packet.Length - 4, declaredLength);
        Assert.Equal(36, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(68, 2)));
        Assert.Equal(5, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(70, 2)));
        Assert.Equal(112, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(96, 4)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(100, 2)));
    }

    [Fact]
    public void Smb1NegotiatePacket_HasConsistentLengthsAndFiveDialects()
    {
        var packet = SmbProbe.Smb1NegotiatePacket;
        var declaredLength = packet[1] << 16 | packet[2] << 8 | packet[3];

        Assert.Equal(packet.Length - 4, declaredLength);
        Assert.Equal(0, packet[36]);
        Assert.Equal(packet.Length - 39, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(37, 2)));
        Assert.Equal(5, packet[39..].Count(value => value == 0x02));
    }

    [Fact]
    public async Task NegotiateDialectAsync_UsesSmb2First()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var header = new byte[8];
            await stream.ReadExactlyAsync(header);
            Assert.Equal(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }, header[4..8]);
            await stream.WriteAsync(CreateSmb2Response(0x0311));
        });

        var dialect = await SmbProbe.NegotiateDialectAsync("127.0.0.1", port, 2000);

        Assert.Equal("SMBv3.1.1", dialect);
        await server;
    }

    [Fact]
    public async Task NegotiateDialectAsync_ReconnectsForSmb1Fallback()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var server = Task.Run(async () =>
        {
            using (var smb2Client = await listener.AcceptTcpClientAsync())
            {
                var header = new byte[8];
                await smb2Client.GetStream().ReadExactlyAsync(header);
                Assert.Equal(new byte[] { 0xFE, 0x53, 0x4D, 0x42 }, header[4..8]);
            }

            using var smb1Client = await listener.AcceptTcpClientAsync();
            using var smb1Stream = smb1Client.GetStream();
            var smb1Header = new byte[8];
            await smb1Stream.ReadExactlyAsync(smb1Header);
            Assert.Equal(new byte[] { 0xFF, 0x53, 0x4D, 0x42 }, smb1Header[4..8]);
            await smb1Stream.WriteAsync(CreateSmb1Response(dialectIndex: 4));
        });

        var dialect = await SmbProbe.NegotiateDialectAsync("127.0.0.1", port, 2000);

        Assert.Equal("SMBv1 (NT LM 0.12)", dialect);
        await server;
    }

    private static byte[] CreateSmb1Response(ushort dialectIndex, int length = 39)
    {
        var response = new byte[length];
        response[0] = 0x00;
        response[4] = 0xFF;
        response[5] = 0x53;
        response[6] = 0x4D;
        response[7] = 0x42;
        response[8] = 0x72;
        response[36] = 0x11;
        BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(37, 2), dialectIndex);
        return response;
    }

    private static byte[] CreateSmb2Response(ushort dialectRevision)
    {
        var response = new byte[74];
        response[0] = 0x00;
        response[4] = 0xFE;
        response[5] = 0x53;
        response[6] = 0x4D;
        response[7] = 0x42;
        BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(68, 2), 65);
        BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(72, 2), dialectRevision);
        return response;
    }
}
