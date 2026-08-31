using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using LucentMist.Tools;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class SslCertificateToolTests
{
    [Fact]
    public void NormalizeEndpoint_AcceptsUrlAlias()
    {
        var endpoint = SslCertificateTool.NormalizeEndpoint(new ToolArguments
        {
            ["url"] = "https://router.local:8443/status",
        });

        Assert.Equal("router.local", endpoint.Target);
        Assert.Equal(8443, endpoint.Port);
    }

    [Fact]
    public void NormalizeEndpoint_AcceptsPortAliasWithProtocolSuffix()
    {
        var endpoint = SslCertificateTool.NormalizeEndpoint(new ToolArguments
        {
            ["host"] = "router.local",
            ["ssl_port"] = "443/tcp",
        });

        Assert.Equal("router.local", endpoint.Target);
        Assert.Equal(443, endpoint.Port);
    }

    [Fact]
    public void NormalizeEndpoint_ExplicitPortOverridesUrlPort()
    {
        var endpoint = SslCertificateTool.NormalizeEndpoint(new ToolArguments
        {
            ["target"] = "https://router.local:8443",
            ["port"] = "9443",
        });

        Assert.Equal("router.local", endpoint.Target);
        Assert.Equal(9443, endpoint.Port);
    }

    [Fact]
    public void ToolArguments_ParseFlexible_AcceptsJsonNumbersAndArrays()
    {
        var args = ToolArguments.ParseFlexible("{\"target\":\"127.0.0.1\",\"port\":443,\"ports\":[80,443]}");

        Assert.Equal("127.0.0.1", args["target"]);
        Assert.Equal("443", args["port"]);
        Assert.Equal("80,443", args["ports"]);
    }
    private readonly SslCertificateTool _tool = new(new Logger<SslCertificateTool>(NullLoggerFactory.Instance));

    // ============================
    // 输入校验
    // ============================

    [Fact]
    public async Task ExecuteAsync_WithEmptyTarget_ReturnsFailure()
    {
        var args = new ToolArguments { ["target"] = "" };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
        Assert.Contains("必须指定目标", result.Error);
    }

    [Fact]
    public async Task ExecuteAsync_WithMissingTarget_ReturnsFailure()
    {
        var args = new ToolArguments();

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithPortZero_ReturnsFailure()
    {
        var args = new ToolArguments { ["target"] = "example.com", ["port"] = "0" };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
        Assert.Contains("端口号必须在 1-65535 之间", result.Error);
    }

    [Fact]
    public async Task ExecuteAsync_WithPortAbove65535_ReturnsFailure()
    {
        var args = new ToolArguments { ["target"] = "example.com", ["port"] = "65536" };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithNegativePort_ReturnsFailure()
    {
        var args = new ToolArguments { ["target"] = "example.com", ["port"] = "-5" };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task ExecuteAsync_WithInvalidTarget_ReturnsFailureWithoutDns()
    {
        var args = new ToolArguments
        {
            ["target"] = "not a hostname",
            ["timeout_ms"] = "2000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    // ============================
    // 真实 TLS 握手，使用本机随机端口和生成证书，不依赖外网证书/CA/服务状态。
    // ============================

    [Fact]
    public async Task ExecuteAsync_WithLoopbackTls_ReturnsSuccess()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;
        Assert.Equal("127.0.0.1", root.GetProperty("target").GetString());
        Assert.InRange(root.GetProperty("port").GetInt32(), 1, 65535);
    }

    [Fact]
    public async Task ExecuteAsync_ResultContainsAllRequiredFields()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");
        Assert.True(result.Duration > TimeSpan.Zero);

        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;

        // All required fields
        Assert.True(root.TryGetProperty("target", out _));
        Assert.True(root.TryGetProperty("port", out _));
        Assert.True(root.TryGetProperty("subject", out _));
        Assert.True(root.TryGetProperty("issuer", out _));
        Assert.True(root.TryGetProperty("notBefore", out _));
        Assert.True(root.TryGetProperty("notAfter", out _));
        Assert.True(root.TryGetProperty("isExpired", out _));
        Assert.True(root.TryGetProperty("daysRemaining", out _));
        Assert.True(root.TryGetProperty("thumbprint", out _));
        Assert.True(root.TryGetProperty("thumbprintSha256", out _));
        Assert.True(root.TryGetProperty("san", out _));
        Assert.True(root.TryGetProperty("isTrusted", out _));
        Assert.True(root.TryGetProperty("trustErrors", out _));
        Assert.True(root.TryGetProperty("chain", out _));
        Assert.True(root.TryGetProperty("scanDuration", out _));
    }

    [Fact]
    public async Task ExecuteAsync_CertificateFieldsHaveValues()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;

        // Subject should contain CN
        Assert.NotEmpty(root.GetProperty("subject").GetString()!);
        Assert.Contains("CN=", root.GetProperty("subject").GetString());

        // Issuer should not be empty
        Assert.NotEmpty(root.GetProperty("issuer").GetString()!);

        // NotAfter should be a valid date
        var notAfter = root.GetProperty("notAfter").GetString();
        Assert.NotNull(notAfter);
        Assert.True(DateTime.TryParse(notAfter, out _));

        // Thumbprint should be a 40-char hex string (SHA-1)
        var thumbprint = root.GetProperty("thumbprint").GetString();
        Assert.NotNull(thumbprint);
        Assert.True(thumbprint!.Length >= 40);

        // SHA-256 thumbprint: 64 hex chars
        var thumbSha256 = root.GetProperty("thumbprintSha256").GetString();
        Assert.NotNull(thumbSha256);
        Assert.Equal(64, thumbSha256!.Length);

        // The generated certificate is valid for 30 days, independently of any public site.
        Assert.False(root.GetProperty("isExpired").GetBoolean());
    }

    [Fact]
    public async Task ExecuteAsync_SanContainsExactGeneratedDnsAndIpNames()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var san = doc.RootElement.GetProperty("san");

        Assert.Equal(JsonValueKind.Array, san.ValueKind);
        var names = san.EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal(new[] { "127.0.0.1", "::1", "validation.invalid" }, names.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ExecuteAsync_ChainMatchesKnownSelfSignedCertificate()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var chain = doc.RootElement.GetProperty("chain");

        Assert.Equal(JsonValueKind.Array, chain.ValueKind);
        // No root is installed in the machine/user store: this known chain has one element.
        var leaf = Assert.Single(chain.EnumerateArray());
        Assert.Equal(doc.RootElement.GetProperty("thumbprint").GetString(), leaf.GetProperty("thumbprint").GetString());
        Assert.Equal("CN=validation.invalid", leaf.GetProperty("subject").GetString());
    }

    // ============================
    // 非 SSL 端口
    // ============================

    [Fact]
    public async Task ExecuteAsync_WithNonSslPort_ReturnsError()
    {
        var result = await ExecuteAgainstServerAsync(async (stream, token) =>
            await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8.ToArray(), token));

        // Should fail — HTTP port won't complete TLS handshake
        Assert.False(result.Success);
    }

    // ============================
    // 过期证书判断
    // ============================

    [Fact]
    public void EvaluateExpiration_UtcPlusEightBoundary_IsExpired()
    {
        var utcPlusEight = TimeZoneInfo.CreateCustomTimeZone(
            "UTC+08-test",
            TimeSpan.FromHours(8),
            "UTC+08-test",
            "UTC+08-test");
        var nowUtc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=expiry-boundary.invalid",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            new DateTimeOffset(2029, 12, 30, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2030, 1, 1, 7, 0, 0, TimeSpan.FromHours(8)));

        var certificateExpiration = SslCertificateTool.EvaluateExpiration(
            certificate.NotAfter,
            nowUtc);

        Assert.True(certificateExpiration.IsExpired);

        // 07:00 in UTC+8 is 23:00 UTC on the previous day. A direct comparison
        // against 00:00 UTC incorrectly treats the 07:00 wall-clock value as future.
        var certificateLocalNotAfter = new DateTime(
            2030, 1, 1, 7, 0, 0, DateTimeKind.Unspecified);

        var expiration = SslCertificateTool.EvaluateExpiration(
            certificateLocalNotAfter,
            nowUtc,
            utcPlusEight);

        Assert.Equal(
            new DateTime(2029, 12, 31, 23, 0, 0, DateTimeKind.Utc),
            expiration.NotAfterUtc);
        Assert.True(expiration.IsExpired);
    }

    [Fact]
    public void CertificateTimeZone_UnspecifiedValueUsesScannerLocalZone()
    {
        var unspecified = new DateTime(2030, 1, 1, 7, 0, 0, DateTimeKind.Unspecified);
        var utc = DateTime.SpecifyKind(unspecified, DateTimeKind.Utc);

        Assert.Same(TimeZoneInfo.Local, SslCertificateTool.CertificateTimeZone(unspecified));
        Assert.Null(SslCertificateTool.CertificateTimeZone(utc));
    }

    [Fact]
    public async Task ExecuteAsync_DaysRemaining_IsPositiveForValidCert()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);

        var isExpired = doc.RootElement.GetProperty("isExpired").GetBoolean();
        var daysRemaining = doc.RootElement.GetProperty("daysRemaining").GetInt32();

        Assert.False(isExpired);
        Assert.InRange(daysRemaining, 29, 30);
    }

    [Fact]
    public void NormalizeEndpoint_WithDefaultPort_Uses443()
    {
        var args = new ToolArguments
        {
            ["target"] = "127.0.0.1"
        };

        // Test the default independently of whether the host already owns port 443.
        Assert.Equal(443, SslCertificateTool.NormalizeEndpoint(args).Port);
    }

    [Fact]
    public async Task ExecuteAsync_WithSelfSignedCertificate_ReportsUntrustedRoot()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: true);

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;
        Assert.False(root.GetProperty("isTrusted").GetBoolean());
        Assert.Contains(
            root.GetProperty("trustErrors").EnumerateArray().Select(x => x.GetString()),
            error => error == "UntrustedRoot");
    }

    [Fact]
    public async Task ExecuteAsync_WithHostnameMismatch_ReportsNameMismatch()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(includeLoopbackSan: false);

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        Assert.Contains(
            doc.RootElement.GetProperty("trustErrors").EnumerateArray().Select(x => x.GetString()),
            error => error == "NameMismatch");
    }

    [Fact]
    public async Task ExecuteAsync_WithExpiredCertificate_MarksChainElementExpired()
    {
        var result = await ExecuteAgainstSelfSignedServerAsync(
            includeLoopbackSan: true,
            expired: true);

        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        var chainElement = Assert.Single(
            doc.RootElement.GetProperty("chain").EnumerateArray());
        Assert.True(chainElement.GetProperty("isExpired").GetBoolean());
        Assert.True(chainElement.GetProperty("daysRemaining").GetInt32() < 0);
        Assert.True(chainElement.TryGetProperty("notAfterUtc", out _));
    }

    private async Task<ToolResult> ExecuteAgainstSelfSignedServerAsync(
        bool includeLoopbackSan,
        bool expired = false)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=validation.invalid",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("validation.invalid");
        if (includeLoopbackSan)
        {
            san.AddIpAddress(IPAddress.Loopback);
            san.AddIpAddress(IPAddress.IPv6Loopback);
        }
        request.CertificateExtensions.Add(san.Build());
        var notBefore = expired
            ? DateTimeOffset.UtcNow.AddDays(-2)
            : DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = expired
            ? DateTimeOffset.UtcNow.AddDays(-1)
            : DateTimeOffset.UtcNow.AddDays(30);
        using var generatedCertificate = request.CreateSelfSigned(notBefore, notAfter);
        using var certificate = X509CertificateLoader.LoadPkcs12(
            generatedCertificate.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        return await ExecuteAgainstServerAsync(async (stream, token) =>
        {
            using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, token);
        });
    }

    private async Task<ToolResult> ExecuteAgainstServerAsync(Func<NetworkStream, CancellationToken, Task> serve)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            await serve(client.GetStream(), timeout.Token);
        });
        try
        {
            var result = await _tool.ExecuteAsync(new ToolArguments
            {
                ["target"] = "127.0.0.1",
                ["port"] = port.ToString(),
                ["timeout_ms"] = "5000"
            }, timeout.Token);
            await serverTask;
            return result;
        }
        finally
        {
            await timeout.CancelAsync();
            listener.Stop();
            try { await serverTask; }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
            catch (SocketException) when (timeout.IsCancellationRequested) { }
        }
    }
}
