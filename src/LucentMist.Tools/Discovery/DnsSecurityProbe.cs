using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Serialization;

namespace LucentMist.Tools.Discovery;

public static class DnsSecurityProbe
{
    private static readonly AsyncLocal<AnalysisScope?> CurrentScope = new();

    /// <summary>One DNS snapshot per target per Agent run; never a process-wide TTL cache.</summary>
    public static IDisposable BeginAnalysisScope()
    {
        var scope = new AnalysisScope(CurrentScope.Value);
        CurrentScope.Value = scope;
        return scope;
    }

    private sealed class AnalysisScope(AnalysisScope? previous) : IDisposable
    {
        internal readonly ConcurrentDictionary<string, Lazy<Task<DnsSecurityResult>>> Snapshots = new(StringComparer.OrdinalIgnoreCase);
        public void Dispose()
        {
            CurrentScope.Value = previous;
            Snapshots.Clear();
        }
    }

    public static Task<DnsSecurityResult> ProbeAsync(
        string target,
        int timeoutMs,
        CancellationToken cancellationToken = default) => SnapshotAsync(target,
            () => ProbeFreshAsync(target, timeoutMs, cancellationToken), cancellationToken);

    internal static Task<DnsSecurityResult> SnapshotAsync(string target, Func<Task<DnsSecurityResult>> probe, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var scope = CurrentScope.Value;
        return (scope == null ? probe() : scope.Snapshots.GetOrAdd(target,
            _ => new Lazy<Task<DnsSecurityResult>>(probe, LazyThreadSafetyMode.ExecutionAndPublication)).Value).WaitAsync(ct);
    }

    private static async Task<DnsSecurityResult> ProbeFreshAsync(string target, int timeoutMs, CancellationToken cancellationToken)
    {
        var versionQuery = BuildQuery("version.bind", 16, 3, recursionDesired: false);
        var recursionQuery = BuildQuery("example.com", 1, 1, recursionDesired: true);
        var versionResponse = await SendAsync(target, 53, versionQuery, timeoutMs, cancellationToken);
        var recursionResponse = await SendAsync(target, 53, recursionQuery, timeoutMs, cancellationToken);
        var version = versionResponse == null ? null : ReadFirstTxt(versionResponse);
        var recursion = recursionResponse == null ? default : ReadHeader(recursionResponse);
        var recursionAvailable = recursionResponse != null && recursion.ResponseCode == 0 &&
                                 recursion.RecursionAvailable && recursion.AnswerCount > 0;
        var ratio = recursionResponse == null ? 0 : recursionResponse.Length / (double)recursionQuery.Length;

        return new DnsSecurityResult(
            version,
            version == null ? versionResponse == null ? "DNS 版本查询无有效响应，无法判断是否公开版本" : "DNS 响应未公开软件版本" : "服务器公开了 DNS 软件版本",
            recursionAvailable,
            recursionAvailable ? "对当前扫描源开放递归；若该服务可从公网访问，可能被用于 DNS 反射/放大攻击" :
                recursionResponse == null ? "DNS 递归查询无有效响应，状态未知，需复测；不能视为已关闭" : "未观察到对当前扫描源开放递归",
            recursionQuery.Length,
            recursionResponse?.Length ?? 0,
            Math.Round(ratio, 2))
        {
            RecursionStatus = recursionResponse == null ? "unknown" : recursionAvailable ? "observed" : "not_observed",
        };
    }

    internal static byte[] BuildQuery(string name, ushort type, ushort @class, bool recursionDesired)
    {
        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[12];
        header.Clear();
        BinaryPrimitives.WriteUInt16BigEndian(header, 0x4C4D);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], recursionDesired ? (ushort)0x0100 : (ushort)0);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        stream.Write(header);
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length); stream.Write(bytes);
        }
        stream.WriteByte(0);
        WriteUInt16(stream, type); WriteUInt16(stream, @class);
        return stream.ToArray();
    }

    internal static DnsHeader ReadHeader(byte[] packet)
    {
        if (packet.Length < 12) return default;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        return new DnsHeader(
            (flags & 0x0080) != 0,
            flags & 0x000F,
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)));
    }

    internal static string? ReadFirstTxt(byte[] packet)
    {
        if (packet.Length < 12) return null;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        var answers = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        var offset = 12;
        for (var i = 0; i < questions; i++)
        {
            if (!SkipName(packet, ref offset) || offset + 4 > packet.Length) return null;
            offset += 4;
        }
        for (var i = 0; i < answers; i++)
        {
            if (!SkipName(packet, ref offset) || offset + 10 > packet.Length) return null;
            var type = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 8, 2));
            offset += 10;
            if (offset + length > packet.Length) return null;
            if (type == 16 && length > 1)
            {
                var textLength = Math.Min(packet[offset], length - 1);
                return Encoding.UTF8.GetString(packet, offset + 1, textLength);
            }
            offset += length;
        }
        return null;
    }

    private static async Task<byte[]?> SendAsync(string target, int port, byte[] query, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Math.Clamp(timeoutMs, 100, 5000));
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(target, port);
            await udp.SendAsync(query, timeout.Token);
            var response = (await udp.ReceiveAsync(timeout.Token)).Buffer;
            return IsResponseTo(query, response) ? response : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    internal static bool IsResponseTo(byte[] query, byte[] response) => response.Length >= query.Length &&
        response[0] == query[0] && response[1] == query[1] && (response[2] & 0x80) != 0 &&
        response[4] == 0 && response[5] == 1 && response.AsSpan(12, query.Length - 12).SequenceEqual(query.AsSpan(12));

    private static bool SkipName(byte[] packet, ref int offset)
    {
        var labels = 0;
        while (offset < packet.Length && labels++ < 128)
        {
            var length = packet[offset++];
            if (length == 0) return true;
            if ((length & 0xC0) == 0xC0)
            {
                if (offset >= packet.Length) return false;
                offset++;
                return true;
            }
            if (length > 63 || offset + length > packet.Length) return false;
            offset += length;
        }
        return false;
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); stream.Write(bytes);
    }

    internal readonly record struct DnsHeader(bool RecursionAvailable, int ResponseCode, int AnswerCount);
}

public sealed record DnsSecurityResult(
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("versionAssessment")] string VersionAssessment,
    [property: JsonPropertyName("recursionAvailable")] bool RecursionAvailable,
    [property: JsonPropertyName("recursionAssessment")] string RecursionAssessment,
    [property: JsonPropertyName("requestBytes")] int RequestBytes,
    [property: JsonPropertyName("responseBytes")] int ResponseBytes,
    [property: JsonPropertyName("amplificationRatio")] double AmplificationRatio)
{
    [JsonPropertyName("recursionStatus")]
    public string? RecursionStatus { get; init; }
    [JsonPropertyName("evidenceId")]
    public string EvidenceId { get; init; } = Guid.NewGuid().ToString("N");
}
