using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LucentMist.Tools.Discovery;

public static class MdnsProbe
{
    public static async Task<string?> ResolveNameAsync(string target, CancellationToken cancellationToken = default)
    {
        if (!IPAddress.TryParse(target, out var address) || address.AddressFamily != AddressFamily.InterNetwork) return null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(750);
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(new IPEndPoint(address, 5353));
            await udp.SendAsync(BuildReversePtrQuery(address), timeout.Token);
            var response = await udp.ReceiveAsync(timeout.Token);
            return ParsePtrAnswers(response.Buffer).FirstOrDefault();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    internal static byte[] BuildReversePtrQuery(IPAddress address)
    {
        var octets = address.GetAddressBytes();
        var name = $"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa";
        using var stream = new MemoryStream();
        stream.Write(new byte[12]);
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length); stream.Write(bytes);
        }
        stream.WriteByte(0); WriteUInt16(stream, 12); WriteUInt16(stream, 0x8001);
        var packet = stream.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 1);
        return packet;
    }

    internal static IReadOnlyList<string> ParsePtrAnswers(byte[] packet)
    {
        var names = new List<string>();
        if (packet.Length < 12) return names;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        var records = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)) +
                      BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(8, 2)) +
                      BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(10, 2));
        var offset = 12;
        for (var i = 0; i < questions; i++)
        {
            if (!TryReadName(packet, ref offset, out _) || offset + 4 > packet.Length) return names;
            offset += 4;
        }
        for (var i = 0; i < records; i++)
        {
            if (!TryReadName(packet, ref offset, out _) || offset + 10 > packet.Length) break;
            var type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2));
            offset += 10;
            if (offset + length > packet.Length) break;
            var rdataOffset = offset;
            if (type == 12 && TryReadName(packet, ref rdataOffset, out var ptr) && !string.IsNullOrWhiteSpace(ptr)) names.Add(ptr.TrimEnd('.'));
            offset += length;
        }
        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool TryReadName(byte[] packet, ref int offset, out string name)
    {
        var labels = new List<string>(); var cursor = offset; var jumped = false; var hops = 0;
        while (cursor < packet.Length && hops++ < 64)
        {
            var length = packet[cursor++];
            if (length == 0) { if (!jumped) offset = cursor; name = string.Join('.', labels); return true; }
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length) break;
                var pointer = ((length & 0x3F) << 8) | packet[cursor++];
                if (!jumped) offset = cursor; cursor = pointer; jumped = true; continue;
            }
            if (length > 63 || cursor + length > packet.Length) break;
            labels.Add(Encoding.UTF8.GetString(packet, cursor, length)); cursor += length;
        }
        name = string.Empty; return false;
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); stream.Write(bytes);
    }
}
