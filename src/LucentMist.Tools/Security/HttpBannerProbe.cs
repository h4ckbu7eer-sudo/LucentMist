using System.Net;
using System.Net.Security;
using System.Text;
using System.Text.RegularExpressions;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Security;

internal static class HttpBannerProbe
{
    internal sealed record HeaderEvidence(string Method, string StatusLine, int HeaderBytes, string? Server, string? PoweredBy, string? Via);
    internal sealed record Result(string? Banner, string Status, string Reason)
    {
        public IReadOnlyList<HeaderEvidence> Responses { get; init; } = [];
        public HttpPageIdentity? PageIdentity { get; init; }
        public string BodyStatus { get; init; } = "not_read";
    }
    internal static bool IsHttpPort(int port) => port is 80 or 443 or 8000 or 8080 or 8443 or 8888;

    internal static string Parse(string headers)
    {
        // HTTP body text must never masquerade as a Server header or origin CPE.
        var end = headers.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (end >= 0) headers = headers[..end];
        var server = Header(headers, "Server");
        var powered = Header(headers, "X-Powered-By");
        return (server == null ? "HTTP (无 Server 头)" : $"HTTP Server: {server}")
            + (powered == null ? "" : $"; X-Powered-By: {powered}");
    }

    private static string? Header(string text, string name)
    {
        var match = Regex.Match(text, $@"^{name}:[ \t]*([^\r\n]*)", RegexOptions.Multiline | RegexOptions.IgnoreCase,
            TimeSpan.FromMilliseconds(100));
        return match.Success && !string.IsNullOrWhiteSpace(match.Groups[1].Value) ? match.Groups[1].Value.Trim() : null;
    }

    internal static async Task<string?> ProbeAsync(string target, int port, int timeoutMs, CancellationToken ct) =>
        (await ProbeDetailedAsync(target, port, timeoutMs, ct)).Banner;

    internal static Task<Result> ProbeDetailedAsync(string target, int port, int timeoutMs, CancellationToken ct) =>
        HttpObservationScope.GetAsync(target, port, () => ProbeFreshAsync(target, port, timeoutMs, ct), ct);

    private static async Task<Result> ProbeFreshAsync(string target, int port, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var budget = Math.Clamp(timeoutMs, 100, 10000);
        timeout.CancelAfter(budget);
        // Input is pinned by the calling target guard. No proxy, cookies or redirects to another target.
        // TLS trust is assessed by ssl_check; reading a public page does not establish trust.
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            MaxResponseHeadersLength = 32,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true },
        };
        using var http = new HttpClient(handler) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        var uri = new UriBuilder(port is 443 or 8443 ? "https" : "http", target, port, "/").Uri;
        string? best = null;
        var failures = new List<string>();
        var evidence = new List<HeaderEvidence>();
        HttpPageIdentity? identity = null;
        var bodyStatus = "not_read";
        var usableGet = false;
        foreach (var method in new[] { HttpMethod.Head, HttpMethod.Get })
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
            if (method == HttpMethod.Head) attempt.CancelAfter(Math.Max(50, budget / 2));
            try
            {
                using var request = new HttpRequestMessage(method, uri) { Version = HttpVersion.Version11 };
                request.Headers.ConnectionClose = true;
                request.Headers.UserAgent.ParseAdd("LucentMist/0.9");
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, attempt.Token);
                string? Value(string key) => response.Headers.TryGetValues(key, out var values)
                    ? string.Join("; ", values) is { Length: > 0 } value ? value : null : null;
                var server = Value("Server");
                var powered = Value("X-Powered-By");
                var status = $"HTTP/{response.Version} {(int)response.StatusCode}";
                var headerSize = Encoding.UTF8.GetByteCount(status + response.Headers + response.Content.Headers + "\r\n");
                evidence.Add(new(method.Method, status, headerSize, server, powered, Value("Via")));
                var banner = Parse($"{status}\r\nServer: {server}\r\nX-Powered-By: {powered}\r\n\r\n");
                if (best == null || server != null || powered != null) best = banner;
                identity ??= HttpPageIdentity.Read("", Value("WWW-Authenticate"));
                if (method == HttpMethod.Get && response.IsSuccessStatusCode)
                {
                    usableGet = true;
                    // Decode HTTP framing, limit decompressed bytes, never persist the full page.
                    try
                    {
                        using var stream = await response.Content.ReadAsStreamAsync(attempt.Token);
                        var bytes = new byte[65536];
                        var count = 0;
                        while (count < bytes.Length)
                        {
                            var n = await stream.ReadAsync(bytes.AsMemory(count), attempt.Token);
                            if (n == 0) break;
                            count += n;
                        }
                        var charset = response.Content.Headers.ContentType?.CharSet?.Trim('"');
                        Encoding encoding;
                        try { encoding = charset == null ? Encoding.UTF8 : Encoding.GetEncoding(charset); }
                        catch (ArgumentException) { encoding = Encoding.UTF8; }
                        var bodyIdentity = HttpPageIdentity.Read(encoding.GetString(bytes, 0, count), Value("WWW-Authenticate"));
                        identity = bodyIdentity with { Vendor = bodyIdentity.Vendor ?? identity.Vendor, Model = bodyIdentity.Model ?? identity.Model };
                        if (!string.IsNullOrWhiteSpace(identity.Generator))
                            best = (best ?? "HTTP (无 Server 头)") + $"; HTTP Generator: {identity.Generator}";
                        bodyStatus = count == bytes.Length ? "bounded_prefix" : "complete";
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException)
                    { bodyStatus = "incomplete"; }
                }
                if (ServiceFingerprint.FromBanner(banner)?.Version != null)
                    return new Result(banner, "version_observed", $"{method} / 响应头公开了可识别服务版本（未经认证的 Banner 证据）")
                    { Responses = evidence, PageIdentity = identity, BodyStatus = bodyStatus };
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is OperationCanceledException or HttpRequestException or IOException)
            { failures.Add($"{method} {ex.GetType().Name}"); }
            if (timeout.IsCancellationRequested) break;
        }
        ct.ThrowIfCancellationRequested();
        return new Result(best, evidence.Count == 2 && usableGet ? "version_not_disclosed" : "probe_incomplete",
            evidence.Count == 2 && usableGet
                ? "服务器在 HEAD/GET / 响应头中未公开可识别版本；网页标题/型号线索不是软件版本，不代表其它路径也不公开"
                : "HTTP Banner 抓取未完成，不能断言服务器未公开版本：" + string.Join("；", failures))
        { Responses = evidence, PageIdentity = identity, BodyStatus = bodyStatus };
    }
}
