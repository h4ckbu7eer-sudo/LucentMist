using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;

namespace LucentMist.Tools.Security;

/// <summary>SMB 协商探测包与响应解析，供所有扫描和验证路径共用。</summary>
public static class SmbProbe
{
    private const int Smb1DialectCount = 5;

    public static readonly byte[] Smb1NegotiatePacket =
    {
        0x00, 0x00, 0x00, 0x79, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00,
        0x00, 0x18, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00,
        0x00, 0x56, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E,
        0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52,
        0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x49, 0x4E, 0x44,
        0x4F, 0x57, 0x53, 0x20, 0x46, 0x4F, 0x52, 0x20, 0x57, 0x4F, 0x52, 0x4B,
        0x47, 0x52, 0x4F, 0x55, 0x50, 0x53, 0x20, 0x33, 0x2E, 0x30, 0x00, 0x02,
        0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4C,
        0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
        0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
    };

    // SMB 3.1.1 requires a negotiate context. This request advertises SHA-512
    // pre-authentication integrity so modern Windows accepts the 3.1.1 dialect.
    public static readonly byte[] Smb2NegotiatePacket =
    {
        0x00, 0x00, 0x00, 0x9E,
        0xFE, 0x53, 0x4D, 0x42,
        0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10,
        0x70, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03,
        0x00, 0x00,
        0x01, 0x00, 0x26, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x20, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    // Kept as a source-compatible alias for callers outside this assembly.
    public static readonly byte[] NegotiatePacket = Smb1NegotiatePacket;

    public static string? ParseNegotiateResponse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 8 || buffer[0] != 0x00)
            return null;

        if (buffer[4] == 0xFE && buffer[5] == 0x53 && buffer[6] == 0x4D && buffer[7] == 0x42)
            return ParseSmb2Response(buffer);

        if (buffer[4] == 0xFF && buffer[5] == 0x53 && buffer[6] == 0x4D && buffer[7] == 0x42)
            return ParseSmb1Response(buffer);

        return null;
    }

    public static async Task<string?> NegotiateDialectAsync(
        string target,
        int port,
        int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var smb2Timeout = Math.Max(1, timeoutMs * 2 / 3);
        var dialect = await SendNegotiateAsync(
            target, port, Smb2NegotiatePacket, smb2Timeout, cancellationToken);
        if (dialect != null)
            return dialect;

        var remaining = timeoutMs - (int)stopwatch.ElapsedMilliseconds;
        if (remaining <= 0)
            return null;

        // A failed protocol negotiation can close the socket. SMB1 fallback must
        // use a new connection instead of writing a second negotiate on that socket.
        return await SendNegotiateAsync(
            target, port, Smb1NegotiatePacket, remaining, cancellationToken);
    }

    internal static Task<string?> NegotiateSmb1DialectAsync(
        string target,
        int port,
        int timeoutMs,
        CancellationToken cancellationToken = default) =>
        SendNegotiateAsync(target, port, Smb1NegotiatePacket, timeoutMs, cancellationToken);

    private static string? ParseSmb1Response(ReadOnlySpan<byte> buffer)
    {
        // Direct TCP header (4) + SMB1 header (32) + WordCount (1).
        // The first response word is DialectIndex at offsets 37-38.
        if (buffer.Length < 39 || buffer[8] != 0x72 || buffer[36] < 1)
            return null;

        var dialectIndex = BinaryPrimitives.ReadUInt16LittleEndian(buffer[37..39]);
        if (dialectIndex == ushort.MaxValue || dialectIndex >= Smb1DialectCount)
            return null;

        return dialectIndex == Smb1DialectCount - 1
            ? "SMBv1 (NT LM 0.12)"
            : $"SMBv1 (dialect index {dialectIndex})";
    }

    private static string? ParseSmb2Response(ReadOnlySpan<byte> buffer)
    {
        // Direct TCP header (4) + SMB2 header (64). The negotiate response body
        // starts at 68; StructureSize is at 68 and DialectRevision is at 72.
        if (buffer.Length < 74 || buffer[16] != 0x00)
            return null;
        if (BinaryPrimitives.ReadUInt16LittleEndian(buffer[68..70]) != 65)
            return null;

        return BinaryPrimitives.ReadUInt16LittleEndian(buffer[72..74]) switch
        {
            0x0202 => "SMBv2.0.2",
            0x0210 => "SMBv2.1",
            0x0300 => "SMBv3.0",
            0x0302 => "SMBv3.0.2",
            0x0311 => "SMBv3.1.1",
            _ => null,
        };
    }

    private static async Task<string?> SendNegotiateAsync(
        string target,
        int port,
        byte[] packet,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Max(1, timeoutMs));

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(target, port, timeout.Token);
            using var stream = client.GetStream();
            await stream.WriteAsync(packet, timeout.Token);
            var response = await ReadNegotiateResponseAsync(stream, timeout.Token);
            return response == null ? null : ParseNegotiateResponse(response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadNegotiateResponseAsync(
        NetworkStream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[512];
        var bytesRead = await stream.ReadAtLeastAsync(
            buffer, 8, throwOnEndOfStream: false, cancellationToken);
        if (bytesRead < 8)
            return null;

        var minimumLength = buffer[4] switch
        {
            0xFE => 74,
            0xFF => 39,
            _ => 8,
        };
        if (bytesRead < minimumLength)
        {
            bytesRead += await stream.ReadAtLeastAsync(
                buffer.AsMemory(bytesRead),
                minimumLength - bytesRead,
                throwOnEndOfStream: false,
                cancellationToken);
        }

        return bytesRead < minimumLength ? null : buffer[..bytesRead];
    }
}
