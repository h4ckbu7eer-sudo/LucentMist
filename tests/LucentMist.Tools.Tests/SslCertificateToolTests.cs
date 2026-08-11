using System.Text.Json;
using LucentMist.Tools;
using LucentMist.Tools.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LucentMist.Tools.Tests;

public class SslCertificateToolTests
{
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
    public async Task ExecuteAsync_WithNonexistentDomain_ReturnsFailure()
    {
        var args = new ToolArguments
        {
            ["target"] = "does-not-exist.example.invalid",
            ["timeout_ms"] = "2000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.False(result.Success);
    }

    // ============================
    // 真实 SSL 测试（依赖网络）
    // ============================

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_WithBaiduDotCom_ReturnsSuccess()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;
        Assert.Equal("baidu.com", root.GetProperty("target").GetString());
        Assert.Equal(443, root.GetProperty("port").GetInt32());
    }

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_ResultContainsAllRequiredFields()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

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
        Assert.True(root.TryGetProperty("chain", out _));
        Assert.True(root.TryGetProperty("scanDuration", out _));
    }

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_CertificateFieldsHaveValues()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

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

        // isExpired should be false for baidu.com
        Assert.False(root.GetProperty("isExpired").GetBoolean());
    }

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_SanContainsBaiduDomains()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var san = doc.RootElement.GetProperty("san");

        Assert.Equal(JsonValueKind.Array, san.ValueKind);
        var names = san.EnumerateArray().Select(e => e.GetString()).ToList();
        // 应包括至少一个 google 域名
        Assert.Contains(names, n => n != null && n.Contains("baidu"));
    }

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_ChainHasMultipleCertificates()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        var chain = doc.RootElement.GetProperty("chain");

        Assert.Equal(JsonValueKind.Array, chain.ValueKind);
        // 证书链通常有 2+ 个证书
        Assert.True(chain.GetArrayLength() >= 2,
            $"Expected chain >= 2, got {chain.GetArrayLength()}");
    }

    // ============================
    // 非 SSL 端口
    // ============================

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_WithNonSslPort_ReturnsError()
    {
        // Connect to baidu.com:80 (HTTP, not HTTPS) — SSL handshake will fail
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "80",
            ["timeout_ms"] = "5000"
        };

        var result = await _tool.ExecuteAsync(args);

        // Should fail — HTTP port won't complete TLS handshake
        Assert.False(result.Success);
    }

    // ============================
    // 过期证书判断
    // ============================

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_DaysRemaining_IsPositiveForValidCert()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["port"] = "443",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);

        var isExpired = doc.RootElement.GetProperty("isExpired").GetBoolean();
        var daysRemaining = doc.RootElement.GetProperty("daysRemaining").GetInt32();

        if (!isExpired)
            Assert.True(daysRemaining >= 0, $"daysRemaining={daysRemaining} should be >= 0");
    }

    [Fact]
    [Trait("Category", "External")]
    public async Task ExecuteAsync_WithDefaultPort_Uses443()
    {
        var args = new ToolArguments
        {
            ["target"] = "baidu.com",
            ["timeout_ms"] = "8000"
        };

        var result = await _tool.ExecuteAsync(args);

        Assert.True(result.Success, result.Error ?? "Expected success");

        using var doc = JsonDocument.Parse(result.Data);
        Assert.Equal(443, doc.RootElement.GetProperty("port").GetInt32());
    }
}
