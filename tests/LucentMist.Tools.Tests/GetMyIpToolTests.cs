using System.Net.NetworkInformation;
using System.Text.Json;
using LucentMist.CLI;
using LucentMist.Core.Networking;
using LucentMist.Tools.Scanning;
using Spectre.Console;

namespace LucentMist.Tools.Tests;

public sealed class GetMyIpToolTests
{
    [Fact]
    public async Task Execute_ReturnsLocalIpAndSuggestedSlash24WithoutExternalCall()
    {
        var tool = new GetMyIpTool(() =>
        [
            new LocalNetworkEntry("Ethernet", "192.168.99.37", 20, "192.168.0.1"),
        ]);

        var result = await tool.ExecuteAsync([]);
        using var doc = JsonDocument.Parse(result.Data);

        Assert.True(result.Success);
        Assert.Equal("192.168.99.37", doc.RootElement.GetProperty("primaryIp").GetString());
        Assert.Equal("192.168.99.0/24", doc.RootElement.GetProperty("suggestedSubnet").GetString());
        var item = Assert.Single(doc.RootElement.GetProperty("interfaces").EnumerateArray());
        Assert.Equal("192.168.0.0/20", item.GetProperty("actualSubnet").GetString());
    }

    [Theory]
    [InlineData("10.20.30.40", 24, "10.20.30.0/24")]
    [InlineData("172.20.31.250", 16, "172.20.0.0/16")]
    [InlineData("192.168.99.37", 20, "192.168.0.0/20")]
    public void ToNetworkCidr_ComputesNetworkBoundary(
        string ip,
        int prefix,
        string expected)
    {
        Assert.Equal(expected, GetMyIpTool.ToNetworkCidr(ip, prefix));
    }

    [Fact]
    public async Task Execute_NoUsableInterface_ReturnsVisibleFailure()
    {
        var result = await new GetMyIpTool(() => []).ExecuteAsync([]);

        Assert.False(result.Success);
        Assert.Contains("未检测到", result.Error);
    }

    [Fact]
    public async Task VirtualAdaptersFirst_ToolAndInjectedContextAgreeOnPhysicalPrimary()
    {
        var entries = new List<LocalNetworkEntry>
        {
            new("VMnet8", "192.168.12.1", 24, "192.168.12.2"),
            new("vEthernet (WSL)", "172.21.0.1", 20, "172.21.0.2"),
            new("WLAN 2", "192.168.99.9", 24, "192.168.99.1")
            {
                InterfaceType = NetworkInterfaceType.Wireless80211,
            },
        };
        var result = await new GetMyIpTool(() => entries).ExecuteAsync([]);
        using var document = JsonDocument.Parse(result.Data);
        var root = document.RootElement;
        var primaryIp = root.GetProperty("primaryIp").GetString();
        var context = LocalNetworkInfo.InjectLocalNetworkInfo("看看我的ip", entries.AsEnumerable().Reverse());

        Assert.Equal("192.168.99.9", primaryIp);
        Assert.Equal("WLAN 2", root.GetProperty("primaryInterface").GetString());
        Assert.Contains($"主 IPv4: {primaryIp}/24", context);
        Assert.Contains("主接口: WLAN 2", context);
        Assert.Contains("另有 2 个虚拟网卡", context);
        Assert.DoesNotContain("192.168.12.1", context);
        var interfaces = root.GetProperty("interfaces").EnumerateArray().ToArray();
        Assert.True(interfaces[0].GetProperty("isVirtual").GetBoolean());
        Assert.True(interfaces[1].GetProperty("isVirtual").GetBoolean());
        Assert.False(interfaces[0].GetProperty("isPrimary").GetBoolean());
        Assert.True(interfaces[2].GetProperty("isPrimary").GetBoolean());

        using var output = new StringWriter();
        var console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            Out = new AnsiConsoleOutput(output),
        });
        console.Profile.Width = 160;
        console.Write(CliApp.BuildLocalIpPanel(root));
        Assert.Contains("192.168.99.9", output.ToString());
        Assert.Contains("虚拟（非主接口）", output.ToString());
        Assert.Contains("VMnet8", output.ToString());
    }

    [Fact]
    public void PrimarySelection_IsStableAcrossPhysicalEnumerationOrder()
    {
        var entries = new[]
        {
            new LocalNetworkEntry("eth1", "10.0.0.2", 24, "10.0.0.1"),
            new LocalNetworkEntry("eth0", "192.168.99.9", 24, "192.168.99.1"),
        };
        Assert.Equal(LocalNetworkInfo.GetPrimaryInterface(entries),
            LocalNetworkInfo.GetPrimaryInterface(entries.Reverse()));
    }

    [Fact]
    public void DefaultGatewayOutranksPrivateInterfaceWithoutGateway()
    {
        var noGateway = new LocalNetworkEntry("Ethernet", "10.0.0.2", 24, "0.0.0.0");
        var primary = new LocalNetworkEntry("wlan0", "192.168.99.9", 24, "192.168.99.1");
        Assert.Equal(primary, LocalNetworkInfo.GetPrimaryInterface([noGateway, primary]));
    }

    [Fact]
    public void NoGateway_FallsBackToPhysicalPrivateAddress()
    {
        var primary = new LocalNetworkEntry("enp3s0", "10.0.0.2", 24, "未知");
        Assert.Equal(primary, LocalNetworkInfo.GetPrimaryInterface([
            new("docker0", "172.17.0.1", 16, "172.17.0.2"), primary]));
    }

    [Theory]
    [InlineData("VMnet8", "", NetworkInterfaceType.Ethernet)]
    [InlineData("Ethernet 2", "VMware Virtual Ethernet Adapter", NetworkInterfaceType.Ethernet)]
    [InlineData("vEthernet (WSL)", "", NetworkInterfaceType.Ethernet)]
    [InlineData("VirtualBox Host-Only", "", NetworkInterfaceType.Ethernet)]
    [InlineData("docker0", "", NetworkInterfaceType.Ethernet)]
    [InlineData("virbr0", "", NetworkInterfaceType.Ethernet)]
    [InlineData("veth012abc", "", NetworkInterfaceType.Ethernet)]
    [InlineData("br-012abc", "", NetworkInterfaceType.Ethernet)]
    [InlineData("tun0", "", NetworkInterfaceType.Ethernet)]
    [InlineData("wg0", "", NetworkInterfaceType.Ethernet)]
    [InlineData("lo", "", NetworkInterfaceType.Loopback)]
    [InlineData("VPN", "", NetworkInterfaceType.Tunnel)]
    [InlineData("Adapter", "Pseudo Interface", NetworkInterfaceType.Ethernet)]
    public void VirtualMetadata_IsExcludedEvenWithGateway(string name, string description, NetworkInterfaceType type)
    {
        var virtualEntry = new LocalNetworkEntry(name, "10.0.0.2", 24, "10.0.0.1")
        {
            Description = description,
            InterfaceType = type,
        };
        Assert.True(virtualEntry.IsVirtual);
        Assert.Null(LocalNetworkInfo.GetPrimaryInterface([virtualEntry]));
    }

    [Fact]
    public void LinuxSysfsVirtualFlag_OverridesPhysicalLookingEthName()
    {
        var container = new LocalNetworkEntry("eth0", "172.17.0.2", 16, "172.17.0.1")
        {
            InterfaceType = NetworkInterfaceType.Ethernet,
            IsVirtualDevice = true,
        };
        Assert.True(container.IsVirtual);
        Assert.Null(LocalNetworkInfo.GetPrimaryInterface([container]));
    }

    [Fact]
    public async Task OnlyVirtualAdapters_ReturnsInventoryWithoutPretendingToHavePhysicalPrimary()
    {
        var entries = new List<LocalNetworkEntry> { new("VMnet8", "192.168.12.1", 24, "192.168.12.2") };
        var result = await new GetMyIpTool(() => entries).ExecuteAsync([]);
        using var document = JsonDocument.Parse(result.Data);
        Assert.True(result.Success);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("primaryIp").ValueKind);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("suggestedSubnet").ValueKind);
        Assert.Single(document.RootElement.GetProperty("interfaces").EnumerateArray());
        Assert.Contains("未检测到可用物理主接口", LocalNetworkInfo.InjectLocalNetworkInfo("我的ip", entries));
    }
}
