using System.Buffers.Binary;
using System.Text;

namespace LucentMist.Tools.Discovery;

internal static class DnsRecords
{
    internal sealed record Record(string Owner, ushort Type, ushort Class, string? Name, string[] Text);

    internal static IReadOnlyList<Record> Read(byte[] packet)
    {
        var results = new List<Record>();
        if (packet.Length < 12 || (packet[2] & 0x80) == 0 || (packet[2] & 2) != 0) return results;
        var offset = 12;
        var questions = U16(packet, 4);
        for (var i = 0; i < questions; i++)
        {
            if (!ReadName(packet, ref offset, out _) || offset + 4 > packet.Length) return [];
            offset += 4;
        }
        var count = U16(packet, 6) + U16(packet, 8) + U16(packet, 10);
        for (var i = 0; i < count; i++)
        {
            if (!ReadName(packet, ref offset, out var owner) || offset + 10 > packet.Length) return [];
            var type = U16(packet, offset);
            var cls = (ushort)(U16(packet, offset + 2) & 0x7fff);
            var length = U16(packet, offset + 8);
            offset += 10;
            var end = offset + length;
            if (end > packet.Length) return [];
            if (type == 1 && length != 4 || type == 28 && length != 16) return [];
            string? name = null;
            var text = new List<string>();
            if (type is 12 or 6 or 33)
            {
                var cursor = offset + (type == 33 ? 6 : 0);
                if (cursor >= end || !ReadName(packet, ref cursor, out name) || cursor > end) return [];
                if (type == 6 && (!ReadName(packet, ref cursor, out _) || cursor + 20 != end)) return [];
            }
            if (type == 16)
            {
                var cursor = offset;
                while (cursor < end)
                {
                    var size = packet[cursor++];
                    if (cursor + size > end) return [];
                    text.Add(Encoding.UTF8.GetString(packet, cursor, size));
                    cursor += size;
                }
            }
            results.Add(new Record(owner, type, cls, name, text.ToArray()));
            offset = end;
        }
        return results;
    }

    internal static bool ReadName(byte[] packet, ref int offset, out string name)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var total = 0;
        for (var hops = 0; cursor < packet.Length && hops < 64; hops++)
        {
            var size = packet[cursor++];
            if (size == 0)
            {
                if (!jumped) offset = cursor;
                name = string.Join('.', labels);
                return true;
            }
            if ((size & 0xc0) == 0xc0)
            {
                if (cursor >= packet.Length) break;
                var pointer = ((size & 0x3f) << 8) | packet[cursor++];
                if (!jumped) offset = cursor;
                jumped = true;
                cursor = pointer;
                continue;
            }
            total += size + 1;
            if (size > 63 || cursor + size > packet.Length || total > 255) break;
            labels.Add(Encoding.UTF8.GetString(packet, cursor, size));
            cursor += size;
        }
        name = "";
        return false;
    }

    private static ushort U16(byte[] packet, int offset) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
}
