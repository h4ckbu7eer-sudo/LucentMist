using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Tests;

public class CloudCveTests
{
    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("false", false)]
    [InlineData("invalid", false)]
    public void DefaultEnabled_ExplicitOptOutHonored(string? setting, bool enabled) =>
        Assert.Equal(enabled, CveApiClient.IsExternalEnabled(setting));

    [Fact]
    public async Task Default_QueriesThreeRealContracts_WithoutTargetOrBannerLeak()
    {
        var requests = new ConcurrentBag<string>();
        using var http = new HttpClient(new Handler((request, _) =>
        {
            requests.Add(Uri.UnescapeDataString(request.RequestUri!.ToString()));
            return Task.FromResult(Json(request.RequestUri.Host switch
            {
                "cvetodo.com" => """{"data":[{"id":"CVE-2099-0001","description":"candidate","base_score":"8.1"}]}""",
                "cvedb.shodan.io" => """{"cves":[{"cve_id":"CVE-2099-0002","summary":"candidate","cvss_v3":null,"cvss":5.0}]}""",
                _ => """{"vulnerabilities":[{"cve":{"id":"CVE-2099-0003","descriptions":[{"lang":"en","value":"candidate"}]}}]}""",
            }));
        }));
        var report = await CveApiClient.QueryWithStatusAsync("SSH-2.0-OpenSSH_9.8p1 host=192.168.99.1 token=TEST_SECRET", 22,
            http, CveApiClient.IsExternalEnabled(null), CancellationToken.None);
        Assert.Equal(3, requests.Count);
        Assert.All(requests, url => { Assert.DoesNotContain("192.168.99.1", url); Assert.DoesNotContain("TEST_SECRET", url); });
        Assert.Contains(requests, url => url.Contains("cpe23=cpe:2.3:a:openbsd:openssh:9.8:p1:"));
        Assert.Contains(requests, url => url.Contains("cpeName=cpe:2.3:a:openbsd:openssh:9.8:p1:"));
        Assert.Equal(3, report.Items.Count);
        Assert.Equal(8.1, report.Items.Single(d => d.Source == "CVETodo API").CvssScore);
        Assert.Equal(5.0, report.Items.Single(d => d.Source == "Shodan API").CvssScore);
        Assert.All(report.Items, detail => Assert.Equal("unverified", detail.VersionStatus));
        Assert.All(report.Sources, status => Assert.Equal("ok", status.Status));
    }

    [Fact]
    public async Task UnknownHttp_QueriesKeywords_NotInventedNginxCpe()
    {
        var requests = new ConcurrentBag<string>();
        using var http = new HttpClient(new Handler((request, _) =>
        {
            requests.Add(Uri.UnescapeDataString(request.RequestUri!.ToString()));
            return Task.FromResult(Json("""{"data":[],"cves":[],"vulnerabilities":[]}"""));
        }));
        await CveApiClient.QueryWithStatusAsync("HTTP Server: private-router", 80, http, true, CancellationToken.None);
        Assert.Equal(3, requests.Count);
        Assert.Contains(requests, url => url.Contains("product=http server"));
        Assert.All(requests, url => { Assert.DoesNotContain("private-router", url); Assert.DoesNotContain("nginx", url); Assert.DoesNotContain("cpe", url); });
    }

    [Fact]
    public async Task RpcWithoutProductVersion_IsSkippedAsNotApplicable_NotReportedAsNetworkFailure()
    {
        var calls = 0;
        using var http = new HttpClient(new Handler((_, _) =>
        {
            Interlocked.Increment(ref calls);
            throw new InvalidOperationException("must not query a generic RPC protocol token");
        }));

        var report = await CveApiClient.QueryWithStatusAsync(
            "DCE/RPC endpoint mapper（TCP/135 已响应；未返回应用 Banner）",
            135,
            http,
            true,
            CancellationToken.None);

        Assert.Equal(0, calls);
        var status = Assert.Single(report.Sources);
        Assert.Equal("not_applicable", status.Status);
        Assert.Contains("没有足够具体", status.Detail);
        Assert.False(report.IsPartial);
        Assert.False(report.FellBackToBuiltIn);
    }

    [Fact]
    public async Task KnownProductWithoutVersion_RemainsProductKeywordEvidence()
    {
        using var http = new HttpClient(new Handler((request, _) => Task.FromResult(Json(
            request.RequestUri!.Host == "cvetodo.com"
                ? """{"data":[{"id":"CVE-2099-0001","description":"nginx candidate","base_score":"9.8"}]}"""
                : """{"cves":[],"vulnerabilities":[]}"""))));

        var report = await CveApiClient.QueryWithStatusAsync(
            "HTTP Server: nginx",
            80,
            http,
            true,
            CancellationToken.None);

        Assert.Single(report.Items);
        Assert.Equal("product_keyword", report.Items[0].EvidenceScope);
        Assert.False(VulnerabilityScanTool.HasTargetSpecificEvidence(report.Items[0]));
    }

    [Fact]
    public async Task RealAuthenticationDaemon_DoesNotPromoteVendorHitsToWorkstationFindings()
    {
        var requests = new ConcurrentBag<string>();
        using var http = new HttpClient(new Handler((request, _) =>
        {
            requests.Add(Uri.UnescapeDataString(request.RequestUri!.ToString()));
            return Task.FromResult(Json(request.RequestUri.Host == "cvetodo.com"
                ? """{"data":[{"id":"CVE-2099-0001","description":"VMware vCenter candidate","base_score":"9.8"}]}"""
                : """{"cves":[],"vulnerabilities":[]}"""));
        }));
        var report = await CveApiClient.QueryWithStatusAsync("VMware Authentication Daemon Version 1.10", 902,
            http, true, CancellationToken.None);
        Assert.Single(report.Items);
        Assert.Equal("service_keyword", report.Items[0].EvidenceScope);
        Assert.Equal("unverified", report.Items[0].VersionStatus);
        Assert.All(requests, url => { Assert.DoesNotContain("vmware_workstation", url); Assert.DoesNotContain("cpe", url); });
    }

    [Fact]
    public async Task Timeout_IsIsolated_AndAllFailuresExplicitlyFallback()
    {
        using var http = new HttpClient(new Handler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return Json("{}");
        }));
        var report = await CveApiClient.QueryWithStatusAsync("OpenSSH_8.9p1", 22, http, true, CancellationToken.None,
            sourceTimeout: TimeSpan.FromMilliseconds(30));
        Assert.True(report.FellBackToBuiltIn);
        Assert.All(report.Sources, status => Assert.Equal("timeout", status.Status));
        Assert.Contains(CveDatabase.Match(22, "OpenSSH_8.9p1"), e => e.Cve == "CVE-2023-38408");
    }

    [Fact]
    public async Task OneFailure_DoesNotSuppressSuccessfulSources()
    {
        using var http = new HttpClient(new Handler((request, _) => Task.FromResult(request.RequestUri!.Host == "cvetodo.com"
            ? new HttpResponseMessage(HttpStatusCode.TooManyRequests)
            : Json("""{"cves":[],"vulnerabilities":[]}"""))));
        var report = await CveApiClient.QueryWithStatusAsync(null, 80, http, true, CancellationToken.None);
        Assert.False(report.FellBackToBuiltIn);
        Assert.True(report.IsPartial);
        Assert.Equal(2, report.Sources.Count(s => s.Status == "ok"));
        Assert.Contains(report.Sources, s => s.Status == "rate_limited");
    }

    [Fact]
    public async Task ShodanUnknownProduct404_IsAValidEmptyResult_NotCoverageFailure()
    {
        using var http = new HttpClient(new Handler((request, _) => Task.FromResult(
            request.RequestUri!.Host == "cvedb.shodan.io"
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : Json(request.RequestUri.Host == "cvetodo.com"
                    ? """{"data":[]}"""
                    : """{"vulnerabilities":[]}"""))));

        var report = await CveApiClient.QueryWithStatusAsync(
            "HTTP 已响应（未公开 Server 头版本）", 80, http, true, CancellationToken.None);

        Assert.Contains(report.Sources, source => source.Source == "Shodan API" && source.Status == "ok");
        Assert.False(report.IsPartial);
    }

    [Fact]
    public async Task OptOut_MakesNoRequests_AndCancellationPropagates()
    {
        using var http = new HttpClient(new Handler((_, _) => throw new InvalidOperationException("must not query")));
        Assert.Empty((await CveApiClient.QueryWithStatusAsync("OpenSSH_8.9p1", 22, http, false, CancellationToken.None)).Sources);
        using var ct = new CancellationTokenSource();
        ct.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CveApiClient.QueryWithStatusAsync(null, 80, http, true, ct.Token));
    }

    [Fact]
    public async Task FullTool_FailureCannotBecomeSafeAndFallbackIsVisible()
    {
        var tool = new VulnerabilityScanTool(null, null, (_, _, _, _) => Task.FromResult(new[] { 80 }),
            (_, _, _, _) => Task.FromResult(new CveApiClient.QueryReport([], [new("NVD", "timeout", "timeout")])));
        var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "50" });
        Assert.True(result.Success, result.Error);
        using var doc = JsonDocument.Parse(result.Data);
        Assert.True(doc.RootElement.GetProperty("externalFallback").GetBoolean());
        Assert.Equal("未知", doc.RootElement.GetProperty("overallRisk").GetString());
        Assert.Contains("内置匹配", doc.RootElement.GetProperty("cloudNotice").GetString());
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json) };

    [Fact]
    public void CloudCandidateCli_ShowsVersionUnverifiedAndAllSources()
    {
        using var doc = JsonDocument.Parse("""[{"port":80,"cve":"CVE-2099-1000","cvss":9.8,"source":"CVETodo API + NVD"}]""");
        using var output = new StringWriter();
        var console = Spectre.Console.AnsiConsole.Create(new Spectre.Console.AnsiConsoleSettings
        {
            Ansi = Spectre.Console.AnsiSupport.No,
            Out = new Spectre.Console.AnsiConsoleOutput(output),
        });
        console.Profile.Width = 160;
        console.Write(LucentMist.CLI.CliApp.BuildCloudCandidateTable(doc.RootElement));
        Assert.Contains("版本未验证", output.ToString());
        Assert.Contains("CVETodo API + NVD", output.ToString());
        Assert.Contains("CVE-2099-1000", output.ToString());
    }

    [Theory]
    [InlineData("service_keyword")]
    [InlineData("product_keyword")]
    public async Task KeywordHits_DoNotBecomeHighRiskTargetVulnerabilities(string evidenceScope)
    {
        var candidate = new CveApiClient.CveDetail("CVE-2099-1000", "Some unrelated HTTP product", 9.8, "NVD", "review",
            EvidenceScope: evidenceScope);
        var tool = new VulnerabilityScanTool(null, null, (_, _, _, _) => Task.FromResult(new[] { 80 }),
            (_, _, _, _) => Task.FromResult(new CveApiClient.QueryReport([candidate], [new("NVD", "ok", "keyword only")])));
        var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = "127.0.0.1", ["timeout_ms"] = "50" });
        using var doc = JsonDocument.Parse(result.Data);
        var root = doc.RootElement;
        Assert.Equal(0, root.GetProperty("totalFindings").GetInt32());
        Assert.Equal(0, root.GetProperty("criticalCount").GetInt32());
        Assert.Equal(0, root.GetProperty("cloudCandidateCount").GetInt32());
        Assert.Equal(1, root.GetProperty("cloudRawCandidateCount").GetInt32());
        Assert.Equal("unverified", root.GetProperty("cloudCandidates")[0].GetProperty("versionStatus").GetString());
        Assert.NotEqual("安全", root.GetProperty("overallRisk").GetString());
    }

    [Theory]
    [InlineData("product_version")]
    [InlineData("product")]
    public async Task UnverifiedExternalProductHits_RemainLeads_NotTargetFindings(string evidenceScope)
    {
        var candidate = new CveApiClient.CveDetail(
            "CVE-2026-45695",
            "Kopia backup product issue returned by an SSH search",
            9.8,
            "CVETodo API",
            "review vendor advisory",
            VersionStatus: "unverified",
            EvidenceScope: evidenceScope);
        var tool = new VulnerabilityScanTool(null, null, (_, _, _, _) => Task.FromResult(new[] { 22 }),
            (_, _, _, _) => Task.FromResult(new CveApiClient.QueryReport([candidate], [new("CVETodo API", "ok", "search hit")])));

        var result = await tool.ExecuteAsync(new ToolArguments
        {
            ["target"] = "127.0.0.1",
            ["open_ports"] = "22",
            ["timeout_ms"] = "50",
        });
        using var doc = JsonDocument.Parse(result.Data);

        Assert.DoesNotContain(doc.RootElement.GetProperty("findings").EnumerateArray(),
            item => item.GetProperty("cve").GetString() == "CVE-2026-45695");
        Assert.Contains(doc.RootElement.GetProperty("cloudCandidates").EnumerateArray(),
            item => item.GetProperty("cve").GetString() == "CVE-2026-45695");
    }

    [Fact]
    public void ReportCloudFailure_DoesNotProduceAllClear()
    {
        var report = new LucentMist.Tools.Reporting.ReportGenerator.ScanReport();
        using var doc = JsonDocument.Parse("""{"externalPartial":true,"overallRisk":"未知","cloudCandidateCount":10}""");
        LucentMist.CLI.CliApp.ApplyVulnerabilityCoverage(report, "127.0.0.1", doc.RootElement);
        Assert.Contains(report.Warnings, s => s.Contains("云源失败"));
        Assert.Contains(report.Warnings, s => s.Contains("版本未知"));
        Assert.Contains(report.Notes, s => s.Contains("不计为目标漏洞"));
    }

    [Fact]
    public async Task ProtectedTarget_IsRejectedBeforeCloudLookup()
    {
        var tool = new VulnerabilityScanTool((_, _, _, _) => throw new InvalidOperationException("cloud must not run"));
        var result = await tool.ExecuteAsync(new ToolArguments { ["target"] = "169.254.169.254" });
        Assert.False(result.Success);
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(request, cancellationToken);
    }
}
