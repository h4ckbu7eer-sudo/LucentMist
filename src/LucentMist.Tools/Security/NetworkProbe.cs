using System.Net.Sockets;

namespace LucentMist.Tools.Security;

/// <summary>网络探测辅助：带超时的流读取，避免 Task.Delay + DataAvailable 竞态。</summary>
public static class NetworkProbe
{
    public static async Task<byte[]?> ReadAvailableAsync(
        NetworkStream stream, int maxBytes, int timeoutMs)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var buffer = new byte[maxBytes];
        try
        {
            var n = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            return n > 0 ? buffer[..n] : null;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch
        {
            return null;
        }
    }
}
