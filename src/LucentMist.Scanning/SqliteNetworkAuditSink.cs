using LucentMist.Core.Compliance;

namespace LucentMist.Scanning;

public sealed class SqliteNetworkAuditSink(
    ScanStore store,
    string initiator) : INetworkAuditSink
{
    public Task RecordAsync(NetworkAuditEvent auditEvent, CancellationToken ct = default) =>
        store.AppendAuditAsync(
            auditEvent.EventId,
            null,
            auditEvent.Target,
            string.IsNullOrWhiteSpace(auditEvent.Initiator) ? initiator : auditEvent.Initiator,
            auditEvent.Operation,
            auditEvent.Status,
            auditEvent.Summary,
            ct);
}
