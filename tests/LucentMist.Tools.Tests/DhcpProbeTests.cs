using System.Buffers.Binary;
using System.Net;
using LucentMist.CLI;
using LucentMist.Tools.Discovery;

namespace LucentMist.Tools.Tests;

public class DhcpProbeTests
{
    private static byte[] Discover() => DhcpWire.BuildDiscover([2, 17, 34, 51, 68, 85], "android-99", "android-dhcp-13");

    [Fact]
    public void ReferenceDiscover_IsParsedWithoutFakingBootReply()
    {
        var packet = Discover();
        Assert.Equal(1, packet[0]);
        Assert.Equal(0x8000, BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10)));
        var record = DhcpWire.Parse(packet);
        Assert.True(record.Valid);
        Assert.Equal(1, record.MessageType);
        Assert.Equal("android-99", record.Hostname);
        Assert.Equal("android-dhcp-13", record.VendorClass);
        Assert.Equal("02:11:22:33:44:55", record.ClientMac);
        Assert.Equal(new byte[] { 1, 3, 6, 15, 51 }, record.RequestParams);
        Assert.Null(record.OfferedIp);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(5)]
    public void ReplyPreservesExistingFields_AndDecodesServerLeaseMask(byte type)
    {
        var packet = Discover().ToList();
        packet[0] = 2;
        packet[242] = type;
        packet.RemoveAt(packet.Count - 1);
        packet.AddRange([54, 4, 192, 168, 99, 1, 51, 4, 0, 0, 14, 16, 1, 4, 255, 255, 255, 0, 255]);
        var bytes = packet.ToArray();
        IPAddress.Parse("192.168.99.21").GetAddressBytes().CopyTo(bytes, 16);
        var record = DhcpWire.Parse(bytes);
        Assert.True(record.Valid);
        Assert.Equal("android-99", record.Hostname);
        Assert.Equal("192.168.99.21", record.OfferedIp!.ToString());
        Assert.Equal("192.168.99.1", record.ServerIdentifier!.ToString());
        Assert.Equal(3600u, record.LeaseSeconds);
        Assert.Equal("255.255.255.0", record.SubnetMask!.ToString());
    }

    [Fact]
    public void EveryTruncationIsInvalid_NotPartialSuccessAfterMessageType()
    {
        var packet = Discover();
        for (var length = 0; length < packet.Length; length++) Assert.False(DhcpWire.Parse(packet[..length]).Valid);
        var truncatedAfterType = packet[..243].Concat(new byte[] { 12, 20, 65 }).ToArray();
        Assert.False(DhcpWire.Parse(truncatedAfterType).Valid);
    }

    [Theory]
    [InlineData(0, 9)]
    [InlineData(1, 0)]
    [InlineData(2, 16)]
    [InlineData(236, 0)]
    [InlineData(242, 2)]
    public void MalformedHeaderOrRequestReplyMismatchIsRejected(int index, byte value)
    {
        var packet = Discover();
        packet[index] = value;
        Assert.False(DhcpWire.Parse(packet).Valid);
    }

    [Theory]
    [InlineData(54)]
    [InlineData(51)]
    [InlineData(1)]
    public void WrongLengthForFixedOptionsIsRejected(byte option)
    {
        var packet = Discover()[..^1].Concat(new byte[] { option, 1, 0, 255 }).ToArray();
        Assert.False(DhcpWire.Parse(packet).Valid);
    }

    [Fact]
    public void RandomMalformedDatagramsNeverCrashOrInventRecords()
    {
        var random = new Random(321);
        for (var n = 0; n < 1000; n++)
        {
            var bytes = new byte[random.Next(1024)];
            random.NextBytes(bytes);
            _ = DhcpWire.Parse(bytes);
            _ = DhcpProbe.ParseIpDatagram(bytes, IPAddress.Parse("192.168.99.0"), 24, 1, "02:11:22:33:44:55", DateTimeOffset.UtcNow);
        }
    }

    [Fact]
    public void PassiveDiscoverKeepsTrueZeroSource_AndExcludesOurOwnCraftedPacket()
    {
        var payload = Discover();
        var xid = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4));
        var datagram = Datagram(payload, "0.0.0.0", 68, 67);
        var record = Parse(datagram, xid + 1);
        Assert.NotNull(record);
        Assert.Equal("0.0.0.0", record.SourceIp);
        Assert.Equal("passive-sniff", record.SourceMode);
        Assert.Equal("android-99", record.Hostname);
        Assert.Equal(Convert.ToHexString(payload), record.PayloadHex);
        Assert.Null(Parse(datagram, xid));
        Assert.Equal("passive-sniff", DhcpProbe.ParseIpDatagram(datagram, IPAddress.Parse("192.168.99.0"), 24,
            null, "02:11:22:33:44:55", DateTimeOffset.UtcNow)!.SourceMode);
    }

    [Fact]
    public void ActiveResponseRequiresBothTransactionAndClientMac()
    {
        var payload = Discover();
        payload[0] = 2;
        payload[242] = 2;
        var xid = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4));
        var datagram = Datagram(payload, "192.168.99.1", 67, 68);
        Assert.Equal("active-discovery", Parse(datagram, xid)!.SourceMode);
        Assert.Equal("passive-sniff", Parse(datagram, xid + 1)!.SourceMode);
        payload[33]++;
        Assert.Equal("passive-sniff", Parse(Datagram(payload, "192.168.99.1", 67, 68), xid)!.SourceMode);
    }

    [Fact]
    public void RejectsForeignSubnetFragmentsInvalidUdpAndEphemeralSelfSender()
    {
        Assert.Null(Parse(Datagram(Discover(), "10.0.0.1", 68, 67), 0));
        Assert.Null(Parse(Datagram(Discover(), "192.168.99.5", 54321, 67), 0));
        var packet = Datagram(Discover(), "0.0.0.0", 68, 67);
        packet[6] = 0x20;
        Assert.Null(Parse(packet, 0));
        packet[6] = 0;
        packet[24] = 255;
        Assert.Null(Parse(packet, 0));
    }

    [Theory]
    [InlineData("1.1.1.0/24")]
    [InlineData("127.0.0.0/24")]
    [InlineData("192.168.99.5/32")]
    [InlineData("192.168.99.0/23")]
    [InlineData("example.com")]
    public async Task OutOfScopeNeverOpensSockets(string scope)
    {
        Assert.False(DhcpProbe.TryPrivateSubnet(scope, out _, out _));
        var result = await DhcpProbe.CaptureAsync(scope);
        Assert.Equal("scope-rejected", result.Status);
        Assert.Equal(0, result.DiscoverSent);
        Assert.Empty(result.Records);
    }

    [Fact]
    public void ElevatedChildIsOnlySniffer_WithNoDatabaseOrArbitraryOutputPath()
    {
        var child = HomeNetworkCommands.DhcpChildStart("dotnet.exe", "lmist.dll", "192.168.99.0/24", Guid.NewGuid().ToString("N"), false, new());
        Assert.Equal("runas", child.Verb);
        Assert.True(child.UseShellExecute);
        Assert.Equal(new[] { "lmist.dll", "monitor", "sniff-dhcp" }, child.ArgumentList.Take(3));
        Assert.DoesNotContain("--once", child.ArgumentList);
        Assert.DoesNotContain("--output", child.ArgumentList);
        Assert.DoesNotContain("--trust", child.ArgumentList);
    }


    [Theory]
    [InlineData("01010600A03C2AEB000000000000000000000000000000000000000000112233445500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013D0701001122334455390205DC3C0F616E64726F69642D646863702D31360C0D686F73742D6D6F64656C2D3031370C0103060F1A1C333A3B2B726C5000FF00", "00:11:22:33:44:55")]
    [InlineData("01010600B77BF9A100000000000000000000000000000000000000000211223344AA00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013D07010211223344AA390205DC3C0F616E64726F69642D646863702D31360C0D686F73742D6D6F64656C2D3031370C0103060F1A1C333A3B2B726C5000FF00", "02:11:22:33:44:AA")]
    public void RealAndroidDiscover_20260910_PreservesHostnameAndVendor(string hex, string mac)
    {
        // Captured passively on a real LAN; replay is not another live capture.
        var payload = Convert.FromHexString(hex);
        var record = DhcpWire.Parse(payload);
        Assert.True(record.Valid);
        Assert.Equal(1, record.MessageType);
        Assert.Equal("host-model-01", record.Hostname);
        Assert.Equal("android-dhcp-16", record.VendorClass);
        Assert.Equal(mac, record.ClientMac);
        Assert.Equal(new byte[] { 1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108 }, record.RequestParams);
        Assert.Null(record.ServerIdentifier);
        Assert.Null(record.OfferedIp);
        Assert.False(DhcpWire.Parse(payload[..^2]).Valid);
        var observed = Parse(Datagram(payload, "0.0.0.0", 68, 67), 0)!;
        Assert.Equal("passive-sniff", observed.SourceMode);
        Assert.Equal("0.0.0.0", observed.SourceIp);
        Assert.Equal(hex, observed.PayloadHex);
        Assert.Equal(record.Hostname, observed.Hostname);
    }

    [Fact]
    public async Task DelayedUacApprovalDoesNotConsumeResponseBudget()
    {
        var expected = new DhcpCaptureResult("no-response", "fixture", []);
        var actual = await HomeNetworkCommands.RunDhcpChildAsync(() =>
        {
            Thread.Sleep(250);
            return System.Diagnostics.Process.GetCurrentProcess();
        }, (_, token) =>
        {
            Assert.False(token.IsCancellationRequested);
            return Task.FromResult(expected);
        }, TimeSpan.FromMilliseconds(50), default);
        Assert.Same(expected, actual);
    }

    [Fact]
    public async Task DhcpResponseStillHasDeadline_AndCallerCancellationStopsLaunch()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => HomeNetworkCommands.RunDhcpChildAsync(
            System.Diagnostics.Process.GetCurrentProcess, async (_, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return new DhcpCaptureResult("no-response", "unreachable", []);
            }, TimeSpan.FromMilliseconds(50), default));
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        var launches = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => HomeNetworkCommands.RunDhcpChildAsync(() =>
        {
            launches++;
            return System.Diagnostics.Process.GetCurrentProcess();
        }, (_, _) => Task.FromResult(new DhcpCaptureResult("no-response", "fixture", [])),
            TimeSpan.FromSeconds(1), stop.Token));
        Assert.Equal(0, launches);
    }

    private static DhcpResult? Parse(byte[] packet, uint xid) => DhcpProbe.ParseIpDatagram(packet,
        IPAddress.Parse("192.168.99.0"), 24, xid, "02:11:22:33:44:55", DateTimeOffset.UtcNow);

    private static byte[] Datagram(byte[] payload, string source, ushort sourcePort, ushort destinationPort)
    {
        var packet = new byte[28 + payload.Length];
        packet[0] = 0x45;
        packet[9] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Broadcast.GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24), (ushort)(payload.Length + 8));
        payload.CopyTo(packet, 28);
        return packet;
    }
}
