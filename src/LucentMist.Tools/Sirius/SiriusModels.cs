using System.Text.Json.Serialization;

namespace LucentMist.Tools.Sirius;

public record SiriusScanRequest(string Target, string[]? Ports = null, int Timeout = 300);
public record SiriusScanResponse(string TaskId, string Status, string? Message = null);
public record SiriusTaskStatus(string TaskId, string Status, int Progress, string? Message = null);
public record SiriusResult
{
    public string Target { get; set; } = "";
    public string ScanDuration { get; set; } = "";
    public List<SiriusHost> Hosts { get; set; } = new();
}
public record SiriusHost
{
    public string Ip { get; set; } = "";
    public bool IsUp { get; set; }
    public string? OsGuess { get; set; }
    public List<SiriusPort> Ports { get; set; } = new();
}
public record SiriusPort
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "tcp";
    public string State { get; set; } = "open";
    public string Service { get; set; } = "";
    public List<SiriusVuln> Vulns { get; set; } = new();
}
public record SiriusVuln
{
    public string Cve { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public double Cvss { get; set; }
    public string Risk { get; set; } = ""; // critical/high/medium/low
    public string Fix { get; set; } = "";
    public bool Verified { get; set; }
}
