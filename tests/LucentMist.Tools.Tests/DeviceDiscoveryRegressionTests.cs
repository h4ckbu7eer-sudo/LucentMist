using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using LucentMist.Tools.Discovery;
using LucentMist.Tools.Security;
using LucentMist.Tools.Vulnerability;

namespace LucentMist.Tools.Tests;

public class DeviceDiscoveryRegressionTests
{
    [Fact]
    public async Task SubnetScanUsesSharedDeviceModelEvidence_NotNameOnlyLookup()
    {
        var calls = 0;
        var tool = new LucentMist.Tools.Scanning.PingScanTool(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<LucentMist.Tools.Scanning.PingScanTool>.Instance,
            (_, _, _) => Task.FromResult(System.Net.NetworkInformation.IPStatus.Success),
            (_, _, _) => Task.FromResult(false),
            (_, _) => Task.FromResult<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>()),
            (_, _) => throw new InvalidOperationException("Legacy name-only lookup must not run"), new OuiDatabase(),
            (ip, mac, _) =>
            {
                calls++;
                return Task.FromResult(new DeviceIdentity(ip, mac, "ZTE", "router", "ZXHN F660"));
            });
        var result = await tool.ExecuteAsync(new() { ["target"] = "192.168.99.1" });
        Assert.True(result.Success, result.Error);
        Assert.Equal(1, calls);
        using var data = JsonDocument.Parse(result.Data);
        Assert.Equal("ZXHN F660", data.RootElement.GetProperty("deviceDetails")[0].GetProperty("model").GetString());
    }

    [Theory]
    [InlineData("http://192.168.99.1:49152/root.xml", true)]
    [InlineData("http://169.254.169.254/latest", false)]
    [InlineData("http://other.local/root.xml", false)]
    [InlineData("http://user:password@192.168.99.1/root.xml", false)]
    [InlineData("file:///etc/passwd", false)]
    public void UpnpDescriptionCannotEscapeScannedHost(string url, bool accepted) =>
        Assert.Equal(accepted, UpnpProbe.ReadLocation($"HTTP/1.1 200 OK\r\nLOCATION: {url}\r\n\r\n", IPAddress.Parse("192.168.99.1")) != null);

    [Fact]
    public void ExplicitModelIsRead_NotGuessedFromVendorOrAndroidName()
    {
        var zte = UpnpProbe.ParseDescription("<root><device><manufacturer>ZTE</manufacturer><modelName>ZXHN F660</modelName></device></root>");
        Assert.Equal("ZXHN F660", zte.Model);
        var unknown = UpnpProbe.ParseDescription("<root><device><manufacturer>ZTE</manufacturer><friendlyName>android-99.local</friendlyName></device></root>");
        Assert.Null(unknown.Model);
        Assert.Equal("F660", HttpPageIdentity.Read("<title>ZTE F660 Login</title>").Model);
        Assert.Null(HttpPageIdentity.Read("<title>ZTE Login</title>").Model);
        Assert.Throws<System.Xml.XmlException>(() => UpnpProbe.ParseDescription("<!DOCTYPE root [<!ENTITY x SYSTEM 'file:///secret'>]><root>&x;</root>"));
    }

    [Fact]
    public void MdnsKnownServiceDoesNotRequireServiceEnumeration_ButStillRequiresLinkedTxt()
    {
        DnsRecords.Record[] records =
        [
            new("_googlecast._tcp.local", 12, 1, "tv._googlecast._tcp.local", []),
            new("tv._googlecast._tcp.local", 16, 1, null, ["md=Example TV"]),
            new("unrelated.local", 16, 1, null, ["model=Wrong"]),
        ];
        Assert.Equal("Example TV", MdnsProbe.Identify(records, "1.0.0.127.in-addr.arpa", 4).Model);
        Assert.Null(MdnsProbe.Identify(records.Skip(1), "1.0.0.127.in-addr.arpa", 4).Model);
    }

    [Fact]
    public async Task UpnpRealUdpHttpPathReadsDeviceModel()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var serving = Task.Run(async () =>
        {
            var request = await udp.ReceiveAsync(stop.Token);
            Assert.Contains("M-SEARCH * HTTP/1.1", Encoding.ASCII.GetString(request.Buffer));
            var location = $"http://127.0.0.1:{((IPEndPoint)tcp.LocalEndpoint).Port}/root.xml";
            await udp.SendAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nLOCATION: {location}\r\n\r\n"), request.RemoteEndPoint, stop.Token);
            using var connection = await tcp.AcceptTcpClientAsync(stop.Token);
            var stream = connection.GetStream();
            var requestBytes = await stream.ReadAsync(new byte[4096], stop.Token);
            Assert.True(requestBytes > 0);
            const string body = "<root xmlns='urn:schemas-upnp-org:device-1-0'><device><friendlyName>Android TV</friendlyName><manufacturer>Example</manufacturer><modelName>TV-123</modelName></device></root>";
            await stream.WriteAsync(Encoding.UTF8.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}"), stop.Token);
        }, stop.Token);
        var identity = await UpnpProbe.ProbeAsync("127.0.0.1", ((IPEndPoint)udp.Client.LocalEndPoint!).Port, stop.Token);
        await serving;
        Assert.Equal("device_description_observed", identity.Status);
        Assert.Equal("TV-123", identity.Model);
        Assert.Equal("Android TV", identity.Name);
    }

}
