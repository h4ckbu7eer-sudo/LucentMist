using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using LucentMist.Core.Networking;

namespace LucentMist.Tools.Discovery;

/// <summary>One decoded DHCP record: message type + interesting options.</summary>
public sealed record DhcpRecord(
    byte MessageType,
    string? Hostname,      // option 12  — e.g. "Android-C4F2"
    string? VendorClass,   // option 60  — e.g. "MSFT 5.0", "android-dhcp-13"
    byte[]? RequestParams, // option 55  — parameter-request-list (OS fingerprint)
    string? ClientMac,     // chaddr, when readable
    string? ServerMac,     // destination MAC if parsed from an Ethernet frame header
    IPAddress? OfferedIp,  // yiaddr     — the address the server offers
    bool Valid,
    IPAddress? ServerIdentifier = null,
    uint? LeaseSeconds = null,
    IPAddress? SubnetMask = null);

public static class DhcpWire
{
    private const uint Cookie = 0x63825363;

    /// <summary>Build a DHCPDISCOVER (op=1) for the given client MAC.</summary>
    public static byte[] BuildDiscover(byte[] clientMac6, string? hostname = null, string? vendorClass = null)
    {
        var options = new List<byte>();
        AddOption(options, 53, [1]);                       // DHCPDISCOVER
        if (!string.IsNullOrWhiteSpace(hostname))
            AddOption(options, 12, Encoding.UTF8.GetBytes(hostname));
        if (!string.IsNullOrWhiteSpace(vendorClass))
            AddOption(options, 60, Encoding.UTF8.GetBytes(vendorClass));
        AddOption(options, 55, [1, 3, 6, 15, 51]);         // param request: mask,router,dns,domain,lease
        options.Add(255);                                  // end

        // Fixed 236-byte BOOTP header + 4-byte magic cookie @236 + options @240.
        var packet = new byte[240 + options.Count];
        packet[0] = 1;                                     // op = BOOTREQUEST
        packet[1] = 1;                                     // htype = Ethernet
        packet[2] = 6;                                     // hlen
        // packet[3] hops = 0
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(4, 4), (uint)Random.Shared.Next());
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10, 2), 0x8000); // flags: broadcast
        // ciaddr/siaddr/giaddr = 0 (12..28)
        clientMac6.CopyTo(packet.AsSpan(28, 6));           // chaddr 16 bytes @28
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(236, 4), Cookie);
        options.CopyTo(packet.AsSpan(240, options.Count));
        return packet;
    }

    /// <summary>Parse a BOOTP/DHCP response into a <see cref="DhcpRecord"/>.</summary>
    public static DhcpRecord Parse(byte[] packet)
    {
        if (packet.Length < 244) return new(0, null, null, null, null, null, null, false);
        if (packet[0] is not (1 or 2) || packet[1] != 1 || packet[2] != 6)
            return new(0, null, null, null, null, null, null, false);
        if (BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(236, 4)) != Cookie)
            return new(0, null, null, null, null, null, null, false);

        var chaddr = packet.AsSpan(28, 6);
        var clientMac = chaddr[0] == 0 && chaddr[1] == 0 && chaddr[2] == 0 && chaddr[3] == 0 && chaddr[4] == 0 && chaddr[5] == 0
            ? null : MacToString(chaddr);
        var yiaddr = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(16, 4));

        byte msgType = 0;
        string? hostname = null, vendorClass = null;
        var reqParams = new List<byte>();
        IPAddress? serverIdentifier = null, subnetMask = null;
        uint? leaseSeconds = null;
        var ended = false;

        var pos = 240;
        while (pos < packet.Length)
        {
            var code = packet[pos++];
            if (code == 0) continue;                    // padding
            if (code == 255) { ended = true; break; }     // end
            if (pos >= packet.Length) return new(0, null, null, null, null, null, null, false);
            var len = packet[pos++];
            if (pos + len > packet.Length) return new(0, null, null, null, null, null, null, false);
            var val = packet.AsSpan(pos, len);
            pos += len;

            switch (code)
            {
                case 53 when len == 1: msgType = val[0]; break;
                case 12 when len > 0: hostname = TrimAscii(val); break;
                case 60 when len > 0: vendorClass = TrimAscii(val); break;
                case 55: reqParams.AddRange(val.ToArray()); break;
                case 54 when len == 4: serverIdentifier = new IPAddress(val); break;
                case 51 when len == 4: leaseSeconds = BinaryPrimitives.ReadUInt32BigEndian(val); break;
                case 1 when len == 4: subnetMask = new IPAddress(val); break;
                case 53 or 54 or 51 or 1: return new(0, null, null, null, null, null, null, false);
            }
        }

        var valid = ended && (packet[0] == 1 ? msgType == 1 : msgType is 2 or 5);              // DISCOVER/OFFER/ACK (ACK=5)
        return new(msgType, hostname, vendorClass, reqParams.Count > 0 ? reqParams.ToArray() : null,
            clientMac, null,
            yiaddr == 0 ? null : new IPAddress(BitConverter.GetBytes(yiaddr).Reverse().ToArray()),
            valid, serverIdentifier, leaseSeconds, subnetMask);
    }

    /// <summary>Extract the Ethernet source MAC out of a raw (link-layer) frame, if present.</summary>
    public static string? FrameSourceMac(byte[] frame)
    {
        if (frame.Length < 14 || frame[12] != 0x08 || frame[13] != 0x00) return null; // not IPv4/EtherType
        return MacToString(frame.AsSpan(6, 6));          // dst(6)+src(6); src @6
    }

    private static void AddOption(List<byte> options, byte code, ReadOnlySpan<byte> value)
    {
        options.Add(code);
        options.Add((byte)value.Length);
        foreach (var b in value) options.Add(b);
    }
    private static string? TrimAscii(ReadOnlySpan<byte> bytes)
    {
        // Trim trailing nulls/space; require at least one printable ASCII.
        int end = bytes.Length;
        while (end > 0 && (bytes[end - 1] == 0 || bytes[end - 1] == 32)) end--;
        if (end == 0) return null;
        foreach (var b in bytes[..end])
            if (b < 32 || b > 126) return null;         // non-ASCII hostname is junk
        return Encoding.ASCII.GetString(bytes[..end]);
    }
    private static string MacToString(ReadOnlySpan<byte> mac) =>
        string.Join(":", mac.ToArray().Select(b => b.ToString("X2")));
}


public sealed record DhcpResult(string SourceIp, string? Hostname, string? VendorClass,
    byte[]? RequestedParams, DateTimeOffset ObservedAt, string Mac, string SourceMode,
    byte MessageType, string? OfferedIp, string? ServerIdentifier, uint? LeaseSeconds,
    string? SubnetMask, string? RelayIp, string PayloadHex);

public sealed record DhcpCaptureResult(string Status, string Message, DhcpResult[] Records,
    string? InterfaceIp = null, int DiscoverSent = 0);

public sealed record DhcpProbeOptions(int TimeoutMs = 2500, int Retries = 2, int IntervalMs = 1000, int PassiveMs = 8000)
{
    public static DhcpProbeOptions FromEnvironment() => new(
        Read("LMIST_DHCP_TIMEOUT_MS", 2500, 250, 10000),
        Read("LMIST_DHCP_RETRIES", 2, 1, 3),
        Read("LMIST_DHCP_INTERVAL_MS", 1000, 250, 5000),
        Read("LMIST_DHCP_PASSIVE_MS", 8000, 250, 120000));

    private static int Read(string key, int fallback, int min, int max)
    {
        var text = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrEmpty(text)) return fallback;
        if (!int.TryParse(text, out var value) || value < min || value > max)
            throw new ArgumentException($"{key} 必须为 {min}～{max} 的整数。");
        return value;
    }
    public void Validate()
    {
        if (TimeoutMs is < 250 or > 10000 || Retries is < 1 or > 3 ||
            IntervalMs is < 250 or > 5000 || PassiveMs is < 250 or > 120000)
            throw new ArgumentException("DHCP 采集预算超出允许范围。");
    }
}

public static class DhcpProbe
{
    public static bool IsAdministrator
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static async Task<DhcpCaptureResult> CaptureAsync(string subnet, CancellationToken ct = default,
        bool passiveOnly = false, DhcpProbeOptions? options = null)
    {
        options ??= DhcpProbeOptions.FromEnvironment();
        options.Validate();
        var guard = await TargetGuard.ValidateAsync(subnet, ct);
        if (!guard.IsAllowed || guard.RequiresPublicAuthorization || !TryPrivateSubnet(subnet, out var network, out var prefix))
            return new("scope-rejected", "DHCP 仅允许 TargetGuard 批准的私有 IPv4 本地子网。", []);
        if (!OperatingSystem.IsWindows())
            return new("unsupported-platform", "当前 DHCP 接收实现需要 Windows raw socket / SIO_RCVALL；未执行探测。", []);

        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && !LocalNetworkInfo.IsVirtualInterface(
                    new LocalNetworkEntry(n.Name, "", 0, "") { Description = n.Description, InterfaceType = n.NetworkInterfaceType }))
                .SelectMany(n => n.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && a.PrefixLength == prefix &&
                        Contains(network, prefix, a.Address))
                    .Select(a => (Nic: n, Address: a.Address))).ToArray();
            // A limited broadcast reaches the entire link, so a narrower requested
            // subnet must not silently authorize probing the larger local network.
            if (adapters.Length != 1)
                return new("interface-unavailable", "未找到唯一且掩码完全匹配的物理网卡；未广播，不扩大所选子网范围。", []);
            var (nic, address) = adapters[0];
            var mac = nic.GetPhysicalAddress().GetAddressBytes();
            if (mac.Length != 6 || (mac[0] & 1) != 0 || mac.All(b => b == 0))
                return new("interface-unavailable", "物理接口没有有效 Ethernet MAC；未发送 DISCOVER。", [], address.ToString());
            if (!IsAdministrator)
                return new("permission-required", "DHCP 监听需要管理员权限；尚未打开 raw socket，也未发送 DISCOVER。", [], address.ToString());

            using var receiver = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            receiver.Bind(new IPEndPoint(address, 0));
            receiver.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
            using var sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sender.EnableBroadcast = true;
            sender.Bind(new IPEndPoint(address, 0));
            // Windows DHCP Client owns UDP 68. The OS selects a source port for
            // this discovery-only sender; servers rejecting it yield no-response.
            var discover = DhcpWire.BuildDiscover(mac, vendorClass: "LucentMist");
            var xid = BinaryPrimitives.ReadUInt32BigEndian(discover.AsSpan(4, 4));
            var macText = string.Join(':', mac.Select(b => b.ToString("X2")));
            var records = new List<DhcpResult>();
            var sent = 0;
            string? sendError = null;
            using var receiveStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var matched = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var receiving = ReceiveAsync();
            try
            {
                if (!passiveOnly)
                {
                    for (var attempt = 0; attempt < options.Retries && !matched.Task.IsCompleted && !receiving.IsCompleted; attempt++)
                    {
                        try
                        {
                            await sender.SendToAsync(discover, SocketFlags.None, new IPEndPoint(IPAddress.Broadcast, 67), ct);
                            sent++;
                        }
                        catch (SocketException ex) { sendError = ex.SocketErrorCode.ToString(); break; }
                        await Task.WhenAny(matched.Task, receiving, Task.Delay(options.TimeoutMs, ct));
                        ct.ThrowIfCancellationRequested();
                        if (attempt + 1 < options.Retries && !matched.Task.IsCompleted && !receiving.IsCompleted)
                            await Task.Delay(options.IntervalMs, ct);
                    }
                }
                // An OFFER for this computer usually says nothing about other
                // clients. Keep the passive window even when discovery succeeds.
                if (!receiving.IsCompleted)
                    await Task.WhenAny(receiving, Task.Delay(options.PassiveMs, ct));
                ct.ThrowIfCancellationRequested();
            }
            finally
            {
                await receiveStop.CancelAsync();
                await receiving;
            }
            var result = records.ToArray();
            var active = result.Where(r => r.SourceMode == "active-discovery").ToArray();
            var relayed = active.Any(r => r.RelayIp != null);
            var status = active.Length > 0 ? relayed ? "relayed-response" : "server-response"
                : result.Length > 0 ? "passive-observations" : sendError != null ? "send-failed" : "no-response";
            var message = active.Length > 0
                ? relayed ? "收到匹配本次 xid/MAC 的 DHCP 应答，giaddr 显示中继；不能据此枚举其它设备租约。"
                    : "收到匹配本次 xid/MAC 的 DHCP 服务器应答；不能据此枚举其它设备租约。"
                : result.Length > 0 ? "未取得本次 DISCOVER 的匹配应答；已记录监听窗口中的其它 DHCP 广播/应答。"
                    : "监听窗口内未取得有效 DHCP 记录；不能判断无 DHCP 服务器，也不能判断设备未广播。";
            if (sendError != null) message += $" 主动发送失败（{sendError}），已尝试被动监听。";
            return new(status, message, result, address.ToString(), sent);

            async Task ReceiveAsync()
            {
                var buffer = new byte[65535];
                try
                {
                    while (records.Count < 128)
                    {
                        var length = await receiver.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, receiveStop.Token);
                        var observed = ParseIpDatagram(buffer.AsSpan(0, length), network, prefix, passiveOnly ? null : xid, macText, DateTimeOffset.UtcNow);
                        if (observed == null) continue;
                        if (!records.Any(r => r.PayloadHex == observed.PayloadHex && r.SourceIp == observed.SourceIp)) records.Add(observed);
                        if (observed.SourceMode == "active-discovery") matched.TrySetResult();
                    }
                }
                catch (OperationCanceledException) when (receiveStop.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (SocketException ex)
        {
            return new(ex.SocketErrorCode == SocketError.AccessDenied ? "permission-denied" : "capture-failed",
                $"DHCP socket 失败（{ex.SocketErrorCode}）；不报告采集成功。", []);
        }
        catch (NetworkInformationException ex)
        {
            return new("interface-unavailable", $"无法读取本地网卡（错误码 {ex.ErrorCode}）；未执行 DHCP 探测。", []);
        }
    }

    internal static DhcpResult? ParseIpDatagram(ReadOnlySpan<byte> packet, IPAddress network, int prefix,
        uint? ownXid, string ownMac, DateTimeOffset at)
    {
        if (packet.Length < 28 || packet[0] >> 4 != 4 || packet[9] != 17) return null;
        var header = (packet[0] & 15) * 4;
        var total = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
        if (header < 20 || total > packet.Length || total < header + 8 ||
            (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2)) & 0x3FFF) != 0) return null;
        var udp = packet.Slice(header, total - header);
        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(udp);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(udp.Slice(2, 2));
        var length = BinaryPrimitives.ReadUInt16BigEndian(udp.Slice(4, 2));
        if (length < 8 || length > udp.Length || length > 4104 ||
            !((sourcePort == 68 && destinationPort == 67) || (sourcePort == 67 && destinationPort is 67 or 68))) return null;
        var payload = udp.Slice(8, length - 8).ToArray();
        var record = DhcpWire.Parse(payload);
        if (!record.Valid || record.ClientMac == null) return null;
        var xid = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4, 4));
        // Never present our crafted DISCOVER as a discovered hostname.
        if (record.MessageType == 1 && xid == ownXid && record.ClientMac == ownMac) return null;
        var source = new IPAddress(packet.Slice(12, 4));
        var destination = new IPAddress(packet.Slice(16, 4));
        if (!source.Equals(IPAddress.Any) && !Contains(network, prefix, source)) return null;
        if (!destination.Equals(IPAddress.Broadcast) && !Contains(network, prefix, destination)) return null;
        if (record.OfferedIp != null && !Contains(network, prefix, record.OfferedIp)) return null;
        if (record.MessageType == 1 && sourcePort != 68 || record.MessageType is 2 or 5 && sourcePort != 67) return null;
        var relay = new IPAddress(payload.AsSpan(24, 4));
        return new(source.ToString(), record.Hostname, record.VendorClass, record.RequestParams, at, record.ClientMac,
            record.MessageType is 2 or 5 && xid == ownXid && record.ClientMac == ownMac ? "active-discovery" : "passive-sniff",
            record.MessageType, record.OfferedIp?.ToString(), record.ServerIdentifier?.ToString(), record.LeaseSeconds,
            record.SubnetMask?.ToString(), relay.Equals(IPAddress.Any) ? null : relay.ToString(), Convert.ToHexString(payload));
    }

    internal static bool TryPrivateSubnet(string subnet, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var parts = subnet.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out prefix) || prefix is < 24 or > 30) return false;
        var b = ip.GetAddressBytes();
        if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168)) return false;
        var value = BinaryPrimitives.ReadUInt32BigEndian(b) & (uint.MaxValue << (32 - prefix));
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        network = new IPAddress(bytes);
        return true;
    }

    private static bool Contains(IPAddress network, int prefix, IPAddress ip) =>
        ip.AddressFamily == AddressFamily.InterNetwork &&
        (BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes()) & (uint.MaxValue << (32 - prefix))) ==
        BinaryPrimitives.ReadUInt32BigEndian(network.GetAddressBytes());
}
