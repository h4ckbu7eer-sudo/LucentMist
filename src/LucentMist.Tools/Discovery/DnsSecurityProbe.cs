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
        => await ProbeWithSenderAsync(target,
            query => SendAsync(target, 53, query, timeoutMs, cancellationToken),
            cancellationToken);

    internal static async Task<DnsSecurityResult> ProbeWithSenderAsync(
        string target,
        Func<byte[], Task<byte[]?>> send,
        CancellationToken cancellationToken = default)
    {
        var versionQuery = BuildQuery("version.bind", 16, 3, recursionDesired: false);
        var recursionQuery = BuildQuery("example.com", 1, 1, recursionDesired: true);
        var hostnameQuery = BuildQuery("hostname.bind", 16, 3, recursionDesired: false);
        var octets = IPAddress.Parse(target).GetAddressBytes();
        var zone = $"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa";
        var soaQuery = BuildQuery(zone, 6, 1, recursionDesired: false);
        // Embedded resolvers commonly rate-limit a burst of CHAOS/A/SOA requests.
        // Recursion is the security decision, so probe it first and retry one
        // missing response before sending optional identity queries.
        cancellationToken.ThrowIfCancellationRequested();
        var recursionResponse = await send(recursionQuery);
        var recursionAttempts = 1;
        if (recursionResponse == null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            recursionResponse = await send(recursionQuery);
            recursionAttempts++;
        }
        async Task<byte[]?> SendIdentity(byte[] query)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await send(query);
        }
        var identityResponses = await Task.WhenAll(
            SendIdentity(versionQuery), SendIdentity(hostnameQuery), SendIdentity(soaQuery));
        var versionResponse = identityResponses[0];
        var queries = new[]
        {
            Describe("version.bind", 16, 3, versionResponse),
            Describe("example.com", 1, 1, recursionResponse),
            Describe("hostname.bind", 16, 3, identityResponses[1]),
            Describe(zone, 6, 1, identityResponses[2]),
        };
        var rawVersion = queries[0].Value;
        var version = NormalizeVersion(rawVersion);
        var recursion = recursionResponse == null ? default : ReadHeader(recursionResponse);
        var recursionAvailable = recursionResponse != null && recursion.ResponseCode == 0 &&
                                 recursion.RecursionAvailable && recursion.AnswerCount > 0;
        var ratio = recursionResponse == null ? 0 : recursionResponse.Length / (double)recursionQuery.Length;

        return new DnsSecurityResult(
            version,
            version == null
                ? rawVersion != null
                    ? $"DNS 返回占位值“{rawVersion}”，未提供可用的软件版本"
                    : versionResponse == null ? "DNS 版本查询无有效响应，无法判断是否公开版本" : "DNS 响应未公开软件版本"
                : "服务器公开了 DNS 软件版本",
            recursionAvailable,
            recursionAvailable ? "对当前扫描源开放递归；若该服务可从公网访问，可能被用于 DNS 反射/放大攻击" :
                recursionResponse == null ? "DNS 递归查询无有效响应，状态未知，需复测；不能视为已关闭" : "未观察到对当前扫描源开放递归",
            recursionQuery.Length,
            recursionResponse?.Length ?? 0,
            Math.Round(ratio, 2))
        {
            RecursionStatus = recursionResponse == null ? "unknown" : recursionAvailable ? "observed" : "not_observed",
            Queries = queries,
            Hostname = queries[2].Value,
            SoaPrimaryName = queries[3].Value,
            RecursionProbeAttempts = recursionAttempts,
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
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
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

    internal static DnsQueryEvidence Describe(string name, ushort type, ushort cls, byte[]? response)
    {
        if (response == null) return new(name, type, cls, "no_valid_response", null, null);
        var header = ReadHeader(response);
        var record = DnsRecords.Read(response).FirstOrDefault(r => r.Type == type && r.Class == cls &&
            (type == 6 || r.Owner.Equals(name, StringComparison.OrdinalIgnoreCase)));
        var value = header.ResponseCode == 0 || type == 6 && header.ResponseCode == 3
            ? type == 16 && record != null ? string.Concat(record.Text) : record?.Name : null;
        if (string.IsNullOrWhiteSpace(value)) value = null;
        var status = header.ResponseCode switch { 5 => "refused", 3 => "nxdomain", 2 => "servfail", 0 => value == null ? "no_value" : "value_observed", _ => "error_response" };
        return new(name, type, cls, status, header.ResponseCode, value);
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

    internal static string? NormalizeVersion(string? value)
    {
        var normalized = value?.Trim().Trim('\0', '"', '\'');
        return string.IsNullOrWhiteSpace(normalized) ||
               normalized.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("unknow", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("hidden", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("not disclosed", StringComparison.OrdinalIgnoreCase)
            ? null
            : normalized;
    }

    private static async Task<byte[]?> SendAsync(string target, int port, byte[] query, int timeoutMs, CancellationToken ct)
    {
        var budget = Math.Clamp(timeoutMs, 100, 5000);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            // Give UDP the caller's full per-transport budget. Halving it before
            // TCP fallback caused slow but valid UDP-only resolvers to be missed.
            timeout.CancelAfter(UdpTimeoutBudget(budget));
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(target, port);
            await udp.SendAsync(query, timeout.Token);
            var response = (await udp.ReceiveAsync(timeout.Token)).Buffer;
            if (IsResponseTo(query, response) && (response[2] & 2) == 0) return response;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }

        // Some appliances intentionally answer CHAOS/version and larger DNS
        // replies only over TCP. A mature probe must honor DNS-over-TCP framing
        // instead of treating a UDP timeout/truncation as "no response".
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(budget);
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(target, port, timeout.Token);
            using var stream = client.GetStream();
            var framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, checked((ushort)query.Length));
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, timeout.Token);
            var prefix = new byte[2];
            if (!await ReadExactlyAsync(stream, prefix, timeout.Token)) return null;
            var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
            if (length is < 12 or > 16 * 1024) return null;
            var response = new byte[length];
            return await ReadExactlyAsync(stream, response, timeout.Token) && IsResponseTo(query, response)
                ? response
                : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }

        static async Task<bool> ReadExactlyAsync(NetworkStream stream, byte[] buffer, CancellationToken token)
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(offset), token);
                if (read == 0) return false;
                offset += read;
            }
            return true;
        }
    }

    internal static int UdpTimeoutBudget(int timeoutMs) => Math.Clamp(timeoutMs, 100, 5000);

    internal static bool IsResponseTo(byte[] query, byte[] response)
    {
        if (query.Length < 12 || response.Length < 12 || response[0] != query[0] || response[1] != query[1] ||
            (response[2] & 0xf8) != 0x80 || response[4] != 0 || response[5] != 1) return false;
        var queryOffset = 12;
        var responseOffset = 12;
        return DnsRecords.ReadName(query, ref queryOffset, out var requested) &&
            DnsRecords.ReadName(response, ref responseOffset, out var answered) &&
            requested.Equals(answered, StringComparison.OrdinalIgnoreCase) &&
            queryOffset + 4 <= query.Length && responseOffset + 4 <= response.Length &&
            query.AsSpan(queryOffset, 4).SequenceEqual(response.AsSpan(responseOffset, 4));
    }

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
    [JsonPropertyName("queries")]
    public IReadOnlyList<DnsQueryEvidence> Queries { get; init; } = [];
    [JsonPropertyName("hostname")]
    public string? Hostname { get; init; }
    [JsonPropertyName("soaPrimaryName")]
    public string? SoaPrimaryName { get; init; }
    [JsonPropertyName("recursionProbeAttempts")]
    public int RecursionProbeAttempts { get; init; } = 1;
}

public sealed record DnsQueryEvidence(string Name, ushort Type, ushort Class, string Status, int? ResponseCode, string? Value);
