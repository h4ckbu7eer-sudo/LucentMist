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

            using var ssl = new SslStream(client.GetStream(), false,
                (sender, certificate, chain, errors) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = requestedTarget,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, cts.Token);

            // 获取证书 — 新建 X509Certificate2 以确保扩展属性可用
            var cert = new X509Certificate2(ssl.RemoteCertificate!);
            if (cert == null)
                return ToolResult.Fail("未获取到证书", sw.Elapsed);

            var result = new
            {
                target = requestedTarget,
                port,
                subject = cert.Subject,
                issuer = cert.Issuer,
                notBefore = cert.NotBefore.ToString("O"),
                notAfter = cert.NotAfter.ToString("O"),
                isExpired = DateTime.UtcNow > cert.NotAfter,
                daysRemaining = (cert.NotAfter - DateTime.UtcNow).Days,
                thumbprint = cert.Thumbprint,
                thumbprintSha256 = GetSha256Thumbprint(cert),
                san = GetSubjectAlternativeNames(cert),
                chain = GetChainInfo(cert),
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

    private List<object> GetChainInfo(X509Certificate2 cert)
    {
        var chain = new List<object>();
        try
        {
            using var chainObj = new X509Chain();
            chainObj.Build(cert);
            foreach (var element in chainObj.ChainElements)
            {
                chain.Add(new
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
        }
        return chain;
    }
}
