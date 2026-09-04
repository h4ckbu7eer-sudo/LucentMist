using System.Text.Json;
using LucentMist.CLI;
using LucentMist.Tools.Vulnerability;
using Spectre.Console;

namespace LucentMist.Tools.Tests;

public class UserTranscriptRegressionTests
{
    [Fact]
    public void ReportPreservesWeakOsEvidenceRatherThanClaimingLinuxAsFact()
    {
        var os = JsonSerializer.SerializeToElement(new { osFamily = "Linux", confidence = 30 });
        var label = CliApp.ReportOsLabel(os);
        Assert.Contains("30%", label);
        Assert.Contains("非确认", label);
        Assert.Contains("启发式", label);
    }

    [Fact]
    public void ReportLabelsLocalRuntimeAsDeterministicLocalEvidence()
    {
        var os = JsonSerializer.SerializeToElement(new
        {
            osFamily = "Windows",
            osVersion = "Microsoft Windows 11",
            confidence = 100,
            evidenceType = "local_runtime",
        });

        var label = CliApp.ReportOsLabel(os);

        Assert.Contains("本机确定证据", label);
        Assert.Contains("100%", label);
        Assert.DoesNotContain("启发式", label);
        Assert.DoesNotContain("非确认", label);
    }

    [Fact]
    public void ReplQuestionPanelDoesNotRenderInternalConversationEnvelope()
    {
        using var output = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings { Ansi = AnsiSupport.No, Out = new AnsiConsoleOutput(output) });
        console.Write(CliApp.CreateAgentQuestionPanel("分析网关"));
        Assert.Contains("分析网关", output.ToString());
        Assert.DoesNotContain("以下历史", output.ToString());
        Assert.DoesNotContain("Role", output.ToString());
    }

    [Fact]
    public void DnsNoResponseIsNotRenderedAsNonDisclosure()
    {
        var dns = JsonSerializer.SerializeToElement(new
        {
            version = (string?)null,
            versionAssessment = "DNS 版本查询无有效响应，无法判断是否公开版本"
        });
        Assert.Contains("无有效响应", CliApp.DnsVersionLabel(dns));
        Assert.DoesNotContain("未公开", CliApp.DnsVersionLabel(dns));
    }

    [Theory]
    [InlineData("220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP", "1.10")]
    [InlineData("220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP", "1.0")]
    public void AdvertisedDaemonVersionBecomesAProtocolFingerprintWithoutInventingAProductCpe(string banner, string version)
    {
        var result = BannerGrabber.ParseGenericBanner(banner);
        var fingerprint = ServiceFingerprint.FromBanner(banner);

        Assert.Equal(version, result?.Version);
        Assert.Equal("VMware Authentication Daemon", result?.Service);
        Assert.Equal("vmware-authd", fingerprint?.ProductKey);
        Assert.Equal(version, fingerprint?.Version);
        Assert.Null(fingerprint?.Cpe);
        Assert.Contains("不能等同", fingerprint?.EvidenceDescription);
    }

    [Fact]
    public async Task WindowsGuessCannotInventRpcVersionWhenNothingWasObserved()
    {
        var result = await new BannerGrabber().GrabAsync("127.0.0.1", 135, 50, "Windows");
        Assert.Null(result?.Version);
    }

    [Fact]
    public void OpenTcp135_IsReportedAsObservedRpcWithoutInventingAVersionOrBanner()
    {
        var evidence = LucentMist.Tools.Security.VulnerabilityScanTool
            .NormalizeObservedServiceEvidence(135, null);
        var fingerprint = ServiceFingerprint.FromBanner(evidence);

        Assert.Contains("TCP/135 已响应", evidence);
        Assert.Contains("未返回应用 Banner", evidence);
        Assert.Equal("windows-rpc", fingerprint?.ProductKey);
        Assert.Null(fingerprint?.Version);
        Assert.Null(fingerprint?.Cpe);
    }

    [Fact]
    public async Task LoopbackHasRealMachineNameWithoutMeaninglessMdnsOrOui()
    {
        var identity = await LucentMist.Tools.Discovery.DeviceDiscovery.EnrichAsync("127.0.0.1");
        Assert.Equal(Environment.MachineName, identity.Name);
        Assert.Equal("not_applicable", identity.MdnsStatus);
        Assert.Null(identity.Mac);
    }

    [Fact]
    public void PublicIpIdentity_DoesNotPretendAsnOrServiceBannerIsHardwareVendor()
    {
        var identity = LucentMist.Tools.Discovery.DeviceDiscovery
            .BuildPublicIdentityWithoutLayer2Evidence("198.44.84.219");

        Assert.Contains("无二层 MAC", identity.Vendor);
        Assert.Contains("未执行局域网 mDNS", identity.Name);
        Assert.Contains("未使用归属运营商冒充设备厂商", identity.IdentityEvidence);
    }

    [Theory]
    [InlineData(LucentMist.Tools.Reporting.ReportGenerator.Format.Html)]
    [InlineData(LucentMist.Tools.Reporting.ReportGenerator.Format.Markdown)]
    [InlineData(LucentMist.Tools.Reporting.ReportGenerator.Format.Csv)]
    public void DeviceIdentityReachesEveryHumanReportFormat(LucentMist.Tools.Reporting.ReportGenerator.Format format)
    {
        var report = new LucentMist.Tools.Reporting.ReportGenerator.ScanReport();
        report.Devices.Add(new() { Ip = "192.0.2.1", Name = "网页：中兴智能路由器", Vendor = "ZTE", Model = "未知", IdentityEvidence = "网页声明不是固件版本" });
        var output = new LucentMist.Tools.Reporting.ReportGenerator().Generate(report, format);
        Assert.Contains("中兴智能路由器", output);
        Assert.Contains("网页声明不是固件版本", output);
        Assert.Contains("ZTE", output);
    }
}
