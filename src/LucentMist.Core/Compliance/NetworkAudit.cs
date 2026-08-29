namespace LucentMist.Core.Compliance;

public sealed record NetworkAuditEvent(
    string EventId,
    string Target,
    string Initiator,
    string Operation,
    string Status,
    string Summary);

public interface INetworkAuditSink
{
    Task RecordAsync(NetworkAuditEvent auditEvent, CancellationToken ct = default);
}
