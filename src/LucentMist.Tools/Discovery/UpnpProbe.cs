using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace LucentMist.Tools.Discovery;

/// <summary>Bounded, target-only SSDP discovery. Reads device descriptions; never invokes SOAP actions.</summary>
public static class UpnpProbe
{
    public sealed record Identity(string? Name, string? Manufacturer, string? Model, string Status);

    public static Task<Identity> ProbeAsync(string target, CancellationToken ct = default) => ProbeAsync(target, 1900, ct);

    internal static async Task<Identity> ProbeAsync(string target, int port, CancellationToken ct)
    {
        if (!IPAddress.TryParse(target, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            return new(null, null, null, "unsupported_address");
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(2500);
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(address, port);
            var request = Encoding.ASCII.GetBytes($"M-SEARCH * HTTP/1.1\r\nHOST: {address}:{port}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n");
            await udp.SendAsync(request, budget.Token);
            var response = Encoding.UTF8.GetString((await udp.ReceiveAsync(budget.Token)).Buffer);
            var location = ReadLocation(response, address);
            if (location == null) return new(null, null, null, "unsafe_or_missing_location");
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
            using var http = new HttpClient(handler);
            using var reply = await http.GetAsync(location, HttpCompletionOption.ResponseHeadersRead, budget.Token);
            if (!reply.IsSuccessStatusCode) return new(null, null, null, "description_http_error");
            await using var stream = await reply.Content.ReadAsStreamAsync(budget.Token);
            var buffer = new byte[32769];
            var length = 0;
            while (length < buffer.Length)
            {
                var count = await stream.ReadAsync(buffer.AsMemory(length), budget.Token);
                if (count == 0) break;
                length += count;
            }
            return length > 32768 ? new(null, null, null, "description_too_large")
                : ParseDescription(Encoding.UTF8.GetString(buffer, 0, length));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or HttpRequestException or IOException or XmlException)
        {
            return new(null, null, null, "no_valid_description");
        }
    }

    internal static Uri? ReadLocation(string response, IPAddress target)
    {
        if (!response.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)) return null;
        var raw = response.Split('\n').Select(line => line.Split(':', 2))
            .FirstOrDefault(pair => pair.Length == 2 && pair[0].Trim().Equals("LOCATION", StringComparison.OrdinalIgnoreCase))?[1].Trim();
        // A target response must not redirect the scanner to other hosts, credentials or metadata endpoints.
        return Uri.TryCreate(raw, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" &&
            string.IsNullOrEmpty(uri.UserInfo) && IPAddress.TryParse(uri.Host, out var host) && host.Equals(target)
            ? uri : null;
    }

    internal static Identity ParseDescription(string xml)
    {
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 32768 });
        var root = XDocument.Load(reader).Root;
        var device = root?.Elements().FirstOrDefault(e => e.Name.LocalName == "device");
        string? Field(string name)
        {
            var text = device?.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();
            return string.IsNullOrWhiteSpace(text) ? null : new string(text.Where(c => !char.IsControl(c)).Take(128).ToArray());
        }
        var model = Field("modelName");
        var number = Field("modelNumber");
        if (number != null && !(model?.Contains(number, StringComparison.OrdinalIgnoreCase) ?? false))
            model = model == null ? number : $"{model} ({number})";
        return new(Field("friendlyName"), Field("manufacturer"), model,
            device == null ? "invalid_description" : "device_description_observed");
    }
}
