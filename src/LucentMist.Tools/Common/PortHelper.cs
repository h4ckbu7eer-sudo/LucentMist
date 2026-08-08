namespace LucentMist.Tools.Common;

public static class PortHelper
{
    private const int MinPort = 1;
    private const int MaxPort = 65535;

    public static IReadOnlyDictionary<int, string> TcpServices { get; } = new Dictionary<int, string>
    {
        [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP",
        [53] = "DNS", [80] = "HTTP", [110] = "POP3", [111] = "RPC",
        [135] = "RPC (DCE)", [139] = "NetBIOS", [143] = "IMAP", [161] = "SNMP",
        [389] = "LDAP", [443] = "HTTPS", [445] = "SMB", [465] = "SMTPS",
        [514] = "Syslog", [587] = "SMTP Submission", [636] = "LDAPS",
        [873] = "RSync", [902] = "VMware", [912] = "VMware", [993] = "IMAPS",
        [995] = "POP3S", [1080] = "SOCKS Proxy", [1194] = "OpenVPN",
        [1433] = "MSSQL", [1521] = "Oracle", [1723] = "PPTP", [1883] = "MQTT",
        [2049] = "NFS", [2375] = "Docker", [2483] = "Oracle DB",
        [3128] = "Squid Proxy", [3306] = "MySQL", [3389] = "RDP",
        [4443] = "VMware HTTPS", [5060] = "SIP", [5353] = "mDNS",
        [5432] = "PostgreSQL", [5672] = "RabbitMQ", [5900] = "VNC",
        [5985] = "WinRM HTTP", [5986] = "WinRM HTTPS", [6379] = "Redis",
        [6443] = "K8s API", [8000] = "HTTP Alt", [8009] = "Tomcat AJP",
        [8080] = "HTTP Alt", [8443] = "HTTPS Alt", [8888] = "HTTP Alt",
        [9000] = "PHP-FPM", [9092] = "Kafka", [9200] = "Elasticsearch",
        [11211] = "Memcached", [27017] = "MongoDB", [50000] = "DB2"
    };

    public static IReadOnlyDictionary<int, string> UdpServices { get; } = new Dictionary<int, string>
    {
        [53] = "DNS", [67] = "DHCP", [68] = "DHCP", [69] = "TFTP",
        [123] = "NTP", [137] = "NetBIOS-NS", [161] = "SNMP",
        [500] = "IKE (IPSec)", [514] = "Syslog", [1900] = "SSDP",
        [5353] = "mDNS"
    };

    private static IReadOnlyDictionary<int, string> ServiceKeys { get; } = new Dictionary<int, string>
    {
        [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp",
        [53] = "dns", [80] = "http", [110] = "pop3", [111] = "rpcbind",
        [135] = "rpc-dce", [139] = "netbios-ssn", [143] = "imap",
        [161] = "snmp", [389] = "ldap", [443] = "https", [445] = "smb",
        [465] = "smtps", [514] = "syslog", [587] = "smtp-submission",
        [636] = "ldaps", [873] = "rsync", [902] = "vmware-auth",
        [912] = "vmware-auth", [993] = "imaps", [995] = "pop3s",
        [1080] = "socks-proxy", [1194] = "openvpn", [1433] = "mssql",
        [1521] = "oracle", [1723] = "pptp", [1883] = "mqtt", [2049] = "nfs",
        [2375] = "docker", [2483] = "oracle-db", [3128] = "squid-proxy",
        [3306] = "mysql", [3389] = "rdp", [4443] = "vmware-https",
        [5060] = "sip", [5353] = "mdns", [5432] = "postgresql",
        [5672] = "rabbitmq", [5900] = "vnc", [5985] = "winrm-http",
        [5986] = "winrm-https", [6379] = "redis", [6443] = "k8s-api",
        [8000] = "http-alt", [8009] = "tomcat-ajp", [8080] = "http-proxy",
        [8443] = "https-alt", [8888] = "http-alt", [9000] = "php-fpm",
        [9092] = "kafka", [9200] = "elasticsearch", [11211] = "memcached",
        [27017] = "mongodb", [50000] = "db2"
    };

    public static List<int> ParsePorts(string? portsStr)
    {
        var ports = new HashSet<int>();
        if (string.IsNullOrWhiteSpace(portsStr))
            return [];

        foreach (var part in portsStr.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.Length == 0)
                continue;

            var range = trimmed.Split('-');
            if (range.Length >= 2 &&
                int.TryParse(range[0], out var start) &&
                int.TryParse(range[1], out var end))
            {
                var from = Math.Max(MinPort, start);
                var to = Math.Min(MaxPort, end);
                for (var port = from; port <= to; port++)
                    ports.Add(port);
            }
            else if (int.TryParse(trimmed, out var port) &&
                     port is >= MinPort and <= MaxPort)
            {
                ports.Add(port);
            }
        }

        return ports.OrderBy(port => port).ToList();
    }

    public static string? GetTcpServiceName(int port) =>
        TcpServices.TryGetValue(port, out var name) ? name : null;

    public static string? GetUdpServiceName(int port) =>
        UdpServices.TryGetValue(port, out var name) ? name : null;

    public static string? GetServiceName(int port) =>
        GetTcpServiceName(port) ?? GetUdpServiceName(port);

    public static string? GetServiceKey(int port) =>
        ServiceKeys.TryGetValue(port, out var key) ? key : null;
}
