using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LucentMist.Tools.Discovery;

public static class MdnsProbe
{
    public static async Task<string?> ResolveNameAsync(string target, CancellationToken cancellationToken = default) =>
        (await ProbeAsync(target, cancellationToken)).Name;

    public sealed record Identity(string? Name, string? Model, string Status, int Queries);

    public static Task<Identity> ProbeAsync(string target, CancellationToken cancellationToken = default) =>
        ProbeAsync(target, 5353, cancellationToken);

    internal static async Task<Identity> ProbeAsync(string target, int port, CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(target, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            return new(null, null, "unsupported_address", 0);
        var records = new List<DnsRecords.Record>();
        var queried = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var reverse = string.Join('.', address.GetAddressBytes().Reverse()) + ".in-addr.arpa";
        const string enumeration = "_services._dns-sd._udp.local";
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(1200);
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(new IPEndPoint(address, port));
            await Query(reverse, 12);
            await Query(enumeration, 12);
            // Some devices answer their service type but not the DNS-SD enumeration query.
            await Query("_googlecast._tcp.local", 12);
            await Query("_device-info._tcp.local", 12);
            while (!timeout.IsCancellationRequested)
            {
                var packet = (await udp.ReceiveAsync(timeout.Token)).Buffer;
                records.AddRange(DnsRecords.Read(packet).Where(r => r.Class == 1));
                if (records.Count > 256) break;
                foreach (var type in records.Where(r => r.Owner == enumeration && r.Type == 12 && r.Name != null)
                    .Select(r => r.Name!).Concat(["_googlecast._tcp.local", "_device-info._tcp.local"]).Distinct().Take(4).ToArray())
                {
                    await Query(type, 12);
                    foreach (var instance in records.Where(r => r.Owner.Equals(type, StringComparison.OrdinalIgnoreCase) && r.Type == 12 && r.Name != null)
                        .Select(r => r.Name!).Distinct().Take(2).ToArray())
                        await Query(instance, 16);
                }
            }

            async Task Query(string name, ushort type)
            {
                if (queried.Count >= 8 || !queried.Add($"{type}:{name}")) return;
                // QU requests a unicast reply; connected socket rejects other devices.
                await udp.SendAsync(DnsSecurityProbe.BuildQuery(name, type, 0x8001, false)
                    .Select((b, i) => i < 2 ? (byte)0 : b).ToArray(), timeout.Token);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException) { }
        return Identify(records, reverse, queried.Count);
    }

    internal static Identity Identify(IEnumerable<DnsRecords.Record> source, string reverse, int queries)
    {
        var records = source.Where(r => r.Class == 1).ToArray();
        var name = records.FirstOrDefault(r => r.Type == 12 && r.Owner.Equals(reverse, StringComparison.OrdinalIgnoreCase))?.Name;
        var types = records.Where(r => r.Type == 12 && r.Owner == "_services._dns-sd._udp.local")
            .Select(r => r.Name).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        types.UnionWith(["_googlecast._tcp.local", "_device-info._tcp.local"]);
        var instances = records.Where(r => r.Type == 12 && types.Contains(r.Owner))
            .Select(r => r.Name).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        var txt = records.Where(r => r.Type == 16 && instances.Contains(r.Owner)).SelectMany(r => r.Text);
        var model = txt.Select(value => value.Split('=', 2))
            .FirstOrDefault(pair => pair.Length == 2 && pair[0].ToLowerInvariant() is "model" or "md" or "ty")?[1];
        name ??= records.FirstOrDefault(r => r.Type == 33 && instances.Contains(r.Owner))?.Name;
        return new(name, model, records.Length == 0 ? "no_valid_unicast_response" : "response_observed", queries);
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
