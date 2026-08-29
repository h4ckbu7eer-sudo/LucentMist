using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using LucentMist.Core.Networking;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Security;

/// <summary>
/// SSL/TLS 证书校验工具 — 获取证书信息，检查有效期、SAN、证书链
/// </summary>
public class SslCertificateTool : INetworkTargetTool
{
    private readonly ILogger<SslCertificateTool> _logger;

    public string Name => "ssl_check";
    public string Description => "获取目标 SSL/TLS 证书信息，检查有效期、SAN、证书链";
    public ToolParameter[] Parameters => [
        new() { Name = "target", Type = "string", Description = "目标域名或IP", Required = true },
        new() { Name = "port", Type = "int", Description = "端口", Required = false, Default = "443" },
        new() { Name = "timeout_ms", Type = "int", Description = "超时(毫秒)", Required = false, Default = "5000" }
    ];

    public SslCertificateTool(ILogger<SslCertificateTool> logger) => _logger = logger;

    public async Task<ToolResult> ExecuteAsync(ToolArguments args, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var target = args.GetOrDefault("target");
        var requestedTarget = target;
        var port = args.GetInt("port", 443);
        var timeout = args.GetInt("timeout_ms", 5000);

        if (string.IsNullOrWhiteSpace(target))
            return ToolResult.Fail("必须指定目标", sw.Elapsed);
        if (port is < 1 or > 65535)
            return ToolResult.Fail("端口号必须在 1-65535 之间", sw.Elapsed);
        var connectTarget = await TargetGuard.ResolveSingleTargetAsync(target, cancellationToken);
        if (connectTarget == null)
            return ToolResult.Fail("扫描目标被安全策略拒绝", sw.Elapsed);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("SslCheck: {Target}:{Port}", target, port);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            using var client = new TcpClient();
            await client.ConnectAsync(connectTarget, port, cts.Token);

            var handshakeTrustErrors = new HashSet<string>(StringComparer.Ordinal);
            using var ssl = new SslStream(client.GetStream(), false,
                (_, _, chain, errors) =>
                {
                    AddSslPolicyErrors(handshakeTrustErrors, errors);
                    if (chain != null)
                        AddChainStatusErrors(handshakeTrustErrors, chain.ChainStatus);
                    return true;
                });
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = requestedTarget,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cts.Token);

            // 获取证书 — 新建 X509Certificate2 以确保扩展属性可用
            var cert = new X509Certificate2(ssl.RemoteCertificate!);
            if (cert == null)
                return ToolResult.Fail("未获取到证书", sw.Elapsed);
            var expiration = EvaluateExpiration(
                cert.NotAfter,
                DateTime.UtcNow,
                CertificateTimeZone(cert.NotAfter));
            var chainInfo = GetChainInfo(cert);
            handshakeTrustErrors.UnionWith(chainInfo.TrustErrors);
            var trustErrors = handshakeTrustErrors
                .Order(StringComparer.Ordinal)
                .ToArray();

            var result = new
            {
                target = requestedTarget,
                port,
                subject = cert.Subject,
                issuer = cert.Issuer,
                notBefore = cert.NotBefore.ToString("O"),
                notAfter = cert.NotAfter.ToString("O"),
                notAfterUtc = expiration.NotAfterUtc.ToString("O"),
                isExpired = expiration.IsExpired,
                daysRemaining = expiration.DaysRemaining,
                thumbprint = cert.Thumbprint,
                thumbprintSha256 = GetSha256Thumbprint(cert),
                san = GetSubjectAlternativeNames(cert),
                isTrusted = trustErrors.Length == 0,
                trustErrors,
                chain = chainInfo.Elements,
                scanDuration = sw.Elapsed.ToString()
            };

            _logger.LogInformation("SslCheck done: {Target}:{Port}, DaysLeft={Days}",
                target, port, result.daysRemaining);
            return ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SslCheck failed for {Target}:{Port}", target, port);
            return ToolResult.Fail(ex.Message, sw.Elapsed);
        }
    }

    internal static CertificateExpiration EvaluateExpiration(
        DateTime certificateNotAfter,
        DateTime utcNow,
        TimeZoneInfo? certificateTimeZone = null)
    {
        var notAfterUtc = certificateTimeZone == null
            ? certificateNotAfter.ToUniversalTime()
            : TimeZoneInfo.ConvertTimeToUtc(
                DateTime.SpecifyKind(certificateNotAfter, DateTimeKind.Unspecified),
                certificateTimeZone);
        var normalizedNow = utcNow.Kind == DateTimeKind.Utc
            ? utcNow
            : utcNow.ToUniversalTime();
        return new CertificateExpiration(
            notAfterUtc,
            normalizedNow > notAfterUtc,
            (notAfterUtc - normalizedNow).Days);
    }

    internal static TimeZoneInfo? CertificateTimeZone(DateTime certificateTime)
    {
        // X509Certificate2 normally exposes NotAfter as local time. Some platform
        // providers return Kind=Unspecified; in that case the wall-clock value is
        // still interpreted in the scanner host's local time zone.
        return certificateTime.Kind == DateTimeKind.Unspecified
            ? TimeZoneInfo.Local
            : null;
    }

    internal readonly record struct CertificateExpiration(
        DateTime NotAfterUtc,
        bool IsExpired,
        int DaysRemaining);

    private static void AddSslPolicyErrors(
        HashSet<string> trustErrors,
        SslPolicyErrors errors)
    {
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
            trustErrors.Add("CertificateNotAvailable");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
            trustErrors.Add("NameMismatch");
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
            trustErrors.Add("ChainErrors");
    }

    private static void AddChainStatusErrors(
        HashSet<string> trustErrors,
        IEnumerable<X509ChainStatus> statuses)
    {
        foreach (var status in statuses)
        {
            foreach (var flag in Enum.GetValues<X509ChainStatusFlags>())
            {
                if (flag != X509ChainStatusFlags.NoError && status.Status.HasFlag(flag))
                    trustErrors.Add(flag.ToString());
            }
        }
    }

    private string GetSha256Thumbprint(X509Certificate2 cert)
    {
        try
        {
            var hash = SHA256.HashData(cert.RawData);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to compute SHA256 thumbprint");
            return "";
        }
    }

    private List<string> GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        var names = new List<string>();
        try
        {
            var sanExt = cert.Extensions["2.5.29.17"];
            if (sanExt != null)
            {
                var asn = new AsnEncodedData(sanExt.Oid, sanExt.RawData);
                var formatted = asn.Format(true); // multi-line: "DNS Name=example.com\nDNS Name=*.example.com"

                foreach (var line in formatted.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("DNS Name="))
                        names.Add(trimmed["DNS Name=".Length..]);
                    else if (trimmed.StartsWith("IP Address="))
                        names.Add(trimmed["IP Address=".Length..]);
                    else if (trimmed.StartsWith("IPAddress="))
                        names.Add(trimmed["IPAddress=".Length..]);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read subject alternative names");
        }

        return names.Distinct().ToList();
    }

    private ChainEvaluation GetChainInfo(X509Certificate2 cert)
    {
        var elements = new List<object>();
        var trustErrors = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            using var chainObj = new X509Chain();
            chainObj.Build(cert);
            AddChainStatusErrors(trustErrors, chainObj.ChainStatus);
            foreach (var element in chainObj.ChainElements)
            {
                elements.Add(new
                {
                    subject = element.Certificate.Subject,
                    issuer = element.Certificate.Issuer,
                    thumbprint = element.Certificate.Thumbprint,
                    notAfter = element.Certificate.NotAfter.ToString("O")
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to build certificate chain");
            trustErrors.Add("ChainBuildFailed");
        }
        return new ChainEvaluation(elements, trustErrors);
    }

    private sealed record ChainEvaluation(
        List<object> Elements,
        HashSet<string> TrustErrors);
}
