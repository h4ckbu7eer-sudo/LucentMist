using LucentMist.Tools.Reporting;

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
                    IsExpired = false
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
                    new() { Port = 445, Service = "SMB", Risk = "高", Description = "EternalBlue 风险" },
                    new() { Port = 80, Service = "HTTP", Risk = "中", Description = "明文传输" },
                    new() { Port = 22, Service = "SSH", Risk = "低", Description = "检查版本" },
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
        Assert.Contains("有效（剩余 150 天）", html);
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
    public void Generate_ReportWithNoVuln_SkipsVulnTable()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1", VulnInfo = null };

        var md = gen.Generate(report, ReportGenerator.Format.Markdown);
        Assert.DoesNotContain("## 漏洞", md);
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
    public void Generate_Csv_NoFindings_ContainsNoVulnRow()
    {
        var gen = new ReportGenerator();
        var report = new ReportGenerator.ScanReport { Target = "127.0.0.1" };

        var csv = gen.Generate(report, ReportGenerator.Format.Csv);

        Assert.Contains("无漏洞", csv);
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
    }
}
