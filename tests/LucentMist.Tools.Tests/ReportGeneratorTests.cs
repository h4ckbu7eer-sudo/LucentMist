using LucentMist.CLI;
using LucentMist.Tools.Reporting;
using LucentMist.Tools.Sirius;

namespace LucentMist.Tools.Tests;

public class ReportGeneratorTests
{
    private static ReportGenerator.ScanReport CreateSampleReport()
    {
        return new ReportGenerator.ScanReport
        {
            Target = "192.168.1.0/24",
            ScanDuration = "5.2s",
            TotalDevices = 254,
            OnlineDevices = 3,
            ScanStatus = "completed",
            StatusMessage = "扫描已完成",
            Scope = new()
            {
                Discovery = "ICMP + TCP 回退",
                TcpPorts = "TCP 1-1000",
                VulnerabilityChecks = "22,80,135,139,445,3389,3306,6379,8080,2375",
                Limitations = "非穷尽扫描"
            },
            Devices = new()
            {
                new() { Ip = "192.168.1.1", IsAlive = true, OsGuess = "Linux" },
                new() { Ip = "192.168.1.100", IsAlive = true, OsGuess = "Windows" },
                new() { Ip = "192.168.1.101", IsAlive = true, OsGuess = "macOS" },
            },
            OpenPorts = new()
            {
                new() { Target = "192.168.1.1", Port = 22, Service = "SSH" },
                new() { Target = "192.168.1.100", Port = 445, Service = "SMB" },
                new() { Target = "192.168.1.101", Port = 80, Service = "HTTP" },
            },
            SslInfo = new()
            {
                new()
                {
                    Target = "baidu.com",
                    Port = 443,
                    Subject = "CN=*.baidu.com",
                    Issuer = "CN=GlobalSign",
                    NotAfter = "2027-01-01",
                    DaysRemaining = 150,
                    IsExpired = false,
                    TrustErrors = new() { "UntrustedRoot", "NameMismatch" }
                }
            },
            VulnInfo = new()
            {
                OverallRisk = "中",
                HighCount = 1,
                MediumCount = 1,
                LowCount = 1,
                Findings = new()
                {
                    new() { Target = "192.168.1.100", Port = 445, Service = "SMB", Cve = "CVE-2017-0144", Risk = "高", Cvss = 8.8, Source = "内置库", Confirmed = false, VerificationDetail = "仅候选", Description = "EternalBlue 风险" },
                    new() { Target = "192.168.1.101", Port = 80, Service = "HTTP", Risk = "中", Source = "内置库", Description = "明文传输" },
                    new() { Target = "192.168.1.1", Port = 22, Service = "SSH", Risk = "低", Source = "内置库", Description = "检查版本" },
                }
            }
        };
    }

    [Fact]
    public void Generate_Json_ContainsAllSections()
    {
        var gen = new ReportGenerator();
        var report = CreateSampleReport();
        var json = gen.Generate(report, ReportGenerator.Format.Json);

        Assert.Contains("192.168.1.0/24", json);
        Assert.Contains("SSH", json);
        Assert.Contains("baidu.com", json);
        Assert.Contains("EternalBlue", json);
    }

    [Fact]
    public void Generate_Markdown_ContainsHeadings()
    {
        var gen = new ReportGenerator();
        var report = CreateSampleReport();
        var md = gen.Generate(report, ReportGenerator.Format.Markdown);

        Assert.Contains("紧急摘要", md);
        Assert.Contains("漏洞", md);
        Assert.Contains("LucentMist", md);
        Assert.Contains("修复建议", md);
        Assert.Contains("网络暴露", md);
        Assert.Contains("`445`", md);
        Assert.Contains("SMB", md);
        Assert.Contains("TLS 证书", md);
        Assert.Contains("CN=GlobalSign", md);
        Assert.Contains("TCP 1-1000", md);
        Assert.Contains("CVE-2017-0144", md);
        Assert.Contains("192.168.1.100", md);
        Assert.Contains("CVSS 8.8", md);
        Assert.Contains("候选", md);
    }

    [Fact]
    public void Generate_Html_ContainsTags()
    {
        var gen = new ReportGenerator();
        var report = CreateSampleReport();
        var html = gen.Generate(report, ReportGenerator.Format.Html);

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("<style>", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("192.168.1.1", html);
        Assert.Contains("Windows", html);
        Assert.Contains("192.168.1.1", html); // device IP always in HTML
    }

    [Fact]
    public void Generate_Html_ContainsOpenPortList()
    {
        var gen = new ReportGenerator();
        var report = CreateSampleReport();
        var html = gen.Generate(report, ReportGenerator.Format.Html);

        Assert.Contains("开放端口", html);
        Assert.Contains("<code>22</code>", html);
        Assert.Contains("<code>445</code>", html);
        Assert.Contains("<code>80</code>", html);
        Assert.Contains("文件共享", html);
    }

    [Fact]
    public void Generate_Html_ContainsTlsCertificateStatus()
    {
        var html = new ReportGenerator().Generate(CreateSampleReport(), ReportGenerator.Format.Html);

        Assert.Contains("TLS 证书", html);
        Assert.Contains("CN=*.baidu.com", html);
        Assert.Contains("CN=GlobalSign", html);
        Assert.Contains("有效期内（剩余 150 天）", html);
        Assert.Contains("不可信根或自签证书", html);
        Assert.Contains("主机名不匹配", html);
        Assert.Contains("UntrustedRoot", html);
        Assert.Contains("NameMismatch", html);
    }

    [Fact]
    public void Generate_EmptyReport_DoesNotCrash()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1" };

        var json = gen.Generate(report, ReportGenerator.Format.Json);
        var md = gen.Generate(report, ReportGenerator.Format.Markdown);
        var html = gen.Generate(report, ReportGenerator.Format.Html);

        Assert.NotNull(json);
        Assert.NotNull(md);
        Assert.NotNull(html);
    }

    [Fact]
    public void Generate_ReportWithNoOpenPorts_SkipsPortTable()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "192.0.2.1" };

        var md = gen.Generate(report, ReportGenerator.Format.Markdown);
        Assert.DoesNotContain("8080", md);
    }

    [Fact]
    public void Generate_ReportWithNoSsl_SkipsSslSection()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1" };

        var md = gen.Generate(report, ReportGenerator.Format.Markdown);
        Assert.DoesNotContain("## SSL", md);
    }

    [Fact]
    public void Generate_ReportWithNoVulnAndIncompleteScan_ShowsWarning()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1", VulnInfo = null };

        var md = gen.Generate(report, ReportGenerator.Format.Markdown);
        Assert.Contains("未执行或未完成漏洞扫描", md);
        Assert.DoesNotContain("✅ 在上述扫描范围内未发现", md);
    }

    [Fact]
    public void Generate_Json_IsValidJson()
    {
        var gen = new ReportGenerator();
        var json = gen.Generate(CreateSampleReport(), ReportGenerator.Format.Json);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.Equal("192.168.1.0/24", doc.RootElement.GetProperty("Target").GetString());
    }

    [Fact]
    public void Generate_Html_DoesNotClaimHistoricalFindingsWereFiltered()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport
        {
            Target = "127.0.0.1",
            Devices = new()
            {
                new() { Ip = "127.0.0.1", IsAlive = true, OsGuess = "Linux" }
            },
            VulnInfo = new()
            {
                Findings = new()
                {
                    new()
                    {
                        Port = 80,
                        Service = "HTTP",
                        Risk = "low",
                        Description = "CVE-1999-0001 old finding",
                        Fix = "review"
                    }
                }
            }
        };

        var html = gen.Generate(report, ReportGenerator.Format.Html);

        Assert.Single(report.VulnInfo!.Findings);
        Assert.Contains("CVE-1999-0001", html);
        Assert.Contains("sum-card total'><div class='val'>1</div>", html);
        Assert.DoesNotContain("已过滤", html);
    }

    [Fact]
    public void Generate_Html_RiskClass_IsWhitelisted()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport
        {
            Target = "127.0.0.1",
            VulnInfo = new()
            {
                Findings = new()
                {
                    new()
                    {
                        Port = 80,
                        Service = "HTTP",
                        Risk = "unsafe_class\" onmouseover=\"alert(1)",
                        Description = "test",
                        Fix = "review"
                    }
                }
            }
        };

        var html = gen.Generate(report, ReportGenerator.Format.Html);

        Assert.DoesNotContain("row-unsafe_class", html);
        Assert.DoesNotContain("badge-unsafe_class", html);
        Assert.Contains("row-low", html);
        Assert.Contains("badge-low", html);
    }

    [Fact]
    public void Generate_Csv_IncompleteScan_DoesNotClaimNoVulnerabilities()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1" };

        var csv = gen.Generate(report, ReportGenerator.Format.Csv);

        Assert.Contains("未执行或未完成漏洞扫描", csv);
        Assert.DoesNotContain("\"无漏洞\"", csv);
    }

    [Fact]
    public void Generate_Csv_ContainsOpenPortsAndTlsCertificates()
    {
        var csv = new ReportGenerator().Generate(CreateSampleReport(), ReportGenerator.Format.Csv);

        Assert.Contains("记录类型,目标,端口,服务,状态", csv);
        Assert.Contains("开放端口", csv);
        Assert.Contains("\"192.168.1.100\",445", csv);
        Assert.Contains("SMB", csv);
        Assert.Contains("TLS 证书", csv);
        Assert.Contains("\"baidu.com\",443", csv);
        Assert.Contains("CN=GlobalSign", csv);
        Assert.Contains("CVE-2017-0144", csv);
        Assert.Contains("内置库", csv);
        Assert.Contains("候选", csv);
    }

    [Fact]
    public void Generate_ZeroDevices_NeverRendersPositiveAllClear()
    {
        var report = new ReportGenerator.ScanReport
        {
            Target = "192.0.2.0/24",
            ScanStatus = "no_targets",
            StatusMessage = "未发现任何在线设备"
        };
        var generator = new ReportGenerator();

        var html = generator.Generate(report, ReportGenerator.Format.Html);
        var markdown = generator.Generate(report, ReportGenerator.Format.Markdown);
        var csv = generator.Generate(report, ReportGenerator.Format.Csv);

        Assert.Contains("未发现任何在线设备", html);
        Assert.Contains("不能得出安全结论", html);
        Assert.DoesNotContain("✅ 未发现漏洞", html);
        Assert.Contains("不能得出“未发现漏洞”结论", markdown);
        Assert.DoesNotContain("\"无漏洞\"", csv);
    }

    [Fact]
    public void Generate_CompletedScanWithoutFindings_CanRenderScopedAllClear()
    {
        var report = new ReportGenerator.ScanReport
        {
            Target = "192.0.2.10",
            ScanStatus = "completed",
            StatusMessage = "扫描已完成",
            OnlineDevices = 1,
            VulnInfo = new()
        };
        var generator = new ReportGenerator();

        Assert.Contains("在已披露的扫描范围内未发现", generator.Generate(report, ReportGenerator.Format.Html));
        Assert.Contains("在上述扫描范围内未发现", generator.Generate(report, ReportGenerator.Format.Markdown));
        Assert.Contains("\"无漏洞\"", generator.Generate(report, ReportGenerator.Format.Csv));
    }

    [Fact]
    public void ApplyCompletionStatus_InformationalNoteDoesNotSuppressScopedAllClear()
    {
        var report = new ReportGenerator.ScanReport
        {
            Target = "192.0.2.10",
            OnlineDevices = 1,
            VulnInfo = new(),
            Notes = { "192.0.2.10: OS 指纹未识别，不影响端口与漏洞候选结论" }
        };

        ReportGenerator.ApplyCompletionStatus(report, 1);

        Assert.Equal("completed", report.ScanStatus);
        var generator = new ReportGenerator();
        Assert.Contains("在已披露的扫描范围内未发现", generator.Generate(report, ReportGenerator.Format.Html));
        Assert.Contains("补充说明", generator.Generate(report, ReportGenerator.Format.Markdown));
        Assert.Contains("OS 指纹未识别", generator.Generate(report, ReportGenerator.Format.Csv));
    }

    [Fact]
    public void ApplyCompletionStatus_CompletenessWarningMakesReportPartial()
    {
        var report = new ReportGenerator.ScanReport
        {
            Warnings = { "192.0.2.10: 漏洞候选检测失败" }
        };

        ReportGenerator.ApplyCompletionStatus(report, 1);

        Assert.Equal("partial", report.ScanStatus);
        Assert.Contains("结果不完整", report.StatusMessage);
    }

    [Fact]
    public void ParseVulnerabilityFinding_PreservesToolContract()
    {
        using var document = System.Text.Json.JsonDocument.Parse("""
            {"port":22,"service":"SSH","banner":"OpenSSH_9.2p1","cve":"CVE-2023-38408","name":"OpenSSH RCE","risk":"high","cvss":8.1,"source":"OSV.dev","confirmed":false,"versionVerified":false,"versionStatus":"unverified","verificationDetail":"未执行 PoC","fix":"upgrade"}
            """);

        var finding = ReportGenerator.ParseVulnerabilityFinding("192.0.2.22", document.RootElement);

        Assert.Equal("192.0.2.22", finding.Target);
        Assert.Equal("CVE-2023-38408", finding.Cve);
        Assert.Equal(8.1, finding.Cvss);
        Assert.Equal("OSV.dev", finding.Source);
        Assert.False(finding.Confirmed);
        Assert.Equal("unverified", finding.VersionStatus);
        Assert.Equal("OpenSSH_9.2p1", finding.Banner);
        Assert.Equal("未执行 PoC", finding.VerificationDetail);
    }

    [Fact]
    public void Generate_AllUserFormats_DistinguishVersionEvidence()
    {
        var report = new ReportGenerator.ScanReport
        {
            Target = "192.0.2.22",
            ScanStatus = "completed",
            StatusMessage = "扫描已完成",
            VulnInfo = new()
            {
                HighCount = 2,
                Findings =
                {
                    new()
                    {
                        Target = "192.0.2.22", Port = 22, Service = "SSH",
                        Cve = "CVE-VERIFIED", Risk = "high", Confirmed = false,
                        VersionStatus = "verified", Description = "version-aware"
                    },
                    new()
                    {
                        Target = "192.0.2.22", Port = 22, Service = "SSH",
                        Cve = "CVE-UNVERIFIED", Risk = "high", Confirmed = false,
                        VersionStatus = "unverified", Description = "keyword-only"
                    }
                }
            }
        };
        var generator = new ReportGenerator();

        foreach (var format in new[]
                 {
                     ReportGenerator.Format.Html,
                     ReportGenerator.Format.Markdown,
                     ReportGenerator.Format.Csv
                 })
        {
            var output = generator.Generate(report, format);
            Assert.Contains("候选（版本已验证）", output);
            Assert.Contains("候选（版本未验证）", output);
        }
    }

    [Theory]
    [InlineData(false, "verified", "⚠候选（版本已验证）")]
    [InlineData(false, "unverified", "⚠候选（版本未验证）")]
    [InlineData(false, "unknown", "⚠候选（版本未知）")]
    [InlineData(true, "unverified", "✔已验证")]
    public void CliConfidenceLabel_ExposesVersionEvidence(
        bool confirmed,
        string versionStatus,
        string expected)
    {
        Assert.Equal(expected, CliApp.VulnerabilityConfidenceLabel(confirmed, versionStatus));
    }

    [Fact]
    public void SiriusConvertToReport_PreservesFindingsFromEveryHost()
    {
        var result = new SiriusResult
        {
            Target = "192.0.2.0/30",
            Hosts =
            {
                new() { Ip = "192.0.2.1", IsUp = true, Ports = { new() { Port = 22, Service = "SSH", Vulns = { new() { Cve = "CVE-A", Name = "A", Risk = "high", Cvss = 8.0, Verified = false } } } } },
                new() { Ip = "192.0.2.2", IsUp = true, Ports = { new() { Port = 445, Service = "SMB", Vulns = { new() { Cve = "CVE-B", Name = "B", Risk = "critical", Cvss = 9.8, Verified = true } } } } }
            }
        };

        var report = SiriusClient.ConvertToReport(result);

        Assert.Equal(2, report.VulnInfo!.Findings.Count);
        Assert.Contains(report.VulnInfo.Findings, finding => finding.Target == "192.0.2.1" && finding.Cve == "CVE-A" && !finding.Confirmed);
        Assert.Contains(report.VulnInfo.Findings, finding => finding.Target == "192.0.2.2" && finding.Cve == "CVE-B" && finding.Confirmed);
        Assert.Equal(1, report.VulnInfo.HighCount);
    }
}
