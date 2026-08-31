using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

internal static class HttpBannerProbe
{
    internal sealed record Result(string? Banner, string Status, string Reason);
    internal static bool IsHttpPort(int port) => port is 80 or 443 or 8000 or 8080 or 8443 or 8888;

    internal static string Parse(string headers)
    {
        // Never interpret response body text (or cookies) as product evidence.
        var end = headers.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (end >= 0) headers = headers[..end];
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

    internal static async Task<string?> ProbeAsync(string target, int port, int timeoutMs, CancellationToken ct) =>
        (await ProbeDetailedAsync(target, port, timeoutMs, ct)).Banner;

    internal static async Task<Result> ProbeDetailedAsync(string target, int port, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var budget = Math.Clamp(timeoutMs, 100, 10000);
        timeout.CancelAfter(budget);
        string? best = null;
        var responses = 0;
        var failures = new List<string>();
        foreach (var method in new[] { "HEAD", "GET" })
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
            if (method == "HEAD") attempt.CancelAfter(Math.Max(50, budget / 2));
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(target, port, attempt.Token);
                using var stream = client.GetStream();
                string? banner;
                if (port is 443 or 8443)
                {
                    // Capture the public HTTP banner only. Trust/identity is separately assessed by ssl_check.
                    using var tls = new SslStream(stream, false, (_, _, _, _) => true);
                    await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = target }, attempt.Token);
                    banner = await ReadAsync(tls);
                }
                else banner = await ReadAsync(stream);
                if (banner == null) failures.Add($"{method} 未收到完整 HTTP 响应头");
                else
                {
                    responses++;
                    if (best == null || banner.Contains("Server:", StringComparison.Ordinal)) best = banner;
                    if (ServiceFingerprint.FromBanner(banner)?.Version != null)
                        return new Result(banner, "version_observed", $"{method} / 响应头公开了可识别服务版本（未经认证的 Banner 证据）");
                }

                async Task<string?> ReadAsync(Stream transport)
                {
                    await transport.WriteAsync(Encoding.ASCII.GetBytes($"{method} / HTTP/1.1\r\nHost: {target}:{port}\r\nConnection: close\r\n\r\n"), attempt.Token);
                    var buffer = new byte[4096];
                    var count = 0;
                    while (count < buffer.Length)
                    {
                        var read = await transport.ReadAsync(buffer.AsMemory(count), attempt.Token);
                        if (read == 0) break;
                        count += read;
                        if (Encoding.ASCII.GetString(buffer, 0, count).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                    }
                    var text = Encoding.ASCII.GetString(buffer, 0, count);
                    return text.StartsWith("HTTP/", StringComparison.Ordinal) && text.Contains("\r\n\r\n", StringComparison.Ordinal) ? Parse(text) : null;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is OperationCanceledException or System.Security.Authentication.AuthenticationException or IOException or SocketException)
            {
                failures.Add($"{method} {ex.GetType().Name}");
            }
            if (timeout.IsCancellationRequested) break;
        }
        ct.ThrowIfCancellationRequested();
        return responses == 2
            ? new Result(best, "version_not_disclosed", "服务器在 HEAD/GET / 响应头中未公开可识别版本；不代表其它路径也不公开")
            : new Result(best, "probe_incomplete", "HTTP Banner 抓取未完成，不能断言服务器未公开版本：" + string.Join("；", failures));
    }
}
