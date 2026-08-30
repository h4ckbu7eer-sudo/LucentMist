using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace LucentMist.Tools.Security;

internal static class HttpBannerProbe
{
    internal static string Parse(string headers)
    {
        static string? Header(string text, string name)
        {
            var match = Regex.Match(text, $@"^{name}:[ \t]*([^\r\n]*)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return match.Success && !string.IsNullOrWhiteSpace(match.Groups[1].Value) ? match.Groups[1].Value.Trim() : null;
        }
        var server = Header(headers, "Server");
        var powered = Header(headers, "X-Powered-By");
        return (server == null ? "HTTP (无 Server 头)" : $"HTTP Server: {server}")
            + (powered == null ? "" : $"; X-Powered-By: {powered}");
    }

    internal static async Task<string?> ProbeAsync(string target, int port, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Math.Clamp(timeoutMs, 100, 10000));
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(target, port, timeout.Token);
            using var stream = client.GetStream();
            if (port is 443 or 8443)
            {
                // Capture the public HTTP banner only. Trust/identity is separately assessed by ssl_check.
                using var tls = new SslStream(stream, false, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = target }, timeout.Token);
                return await ReadAsync(tls);
            }
            return await ReadAsync(stream);

            async Task<string?> ReadAsync(Stream transport)
            {
                await transport.WriteAsync(Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {target}\r\nConnection: close\r\n\r\n"), timeout.Token);
                var buffer = new byte[4096];
                var count = 0;
                while (count < buffer.Length)
                {
                    var read = await transport.ReadAsync(buffer.AsMemory(count), timeout.Token);
                    if (read == 0) break;
                    count += read;
                    if (Encoding.ASCII.GetString(buffer, 0, count).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                }
                var text = Encoding.ASCII.GetString(buffer, 0, count);
                return text.StartsWith("HTTP/", StringComparison.Ordinal) ? Parse(text) : null;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException or System.Security.Authentication.AuthenticationException or IOException or SocketException) { return null; }
    }
}
