using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Monitoring;

public sealed partial class MonitorStore
{
    // Upgrade subnet|ports scopes atomically. Preserve event IDs, explicit MAC trust,
    // first/last seen and per-port timestamps across overlapping legacy recipes.
    private static void MigrateLegacyScopes(SqliteConnection db)
    {
        using var transaction = db.BeginTransaction();
        var legacy = new List<(string Id, MonitorScope Scope)>();
        using (var command = Command(db, transaction, """
            SELECT scope FROM monitor_state WHERE instr(scope,'|')>0
            UNION SELECT scope FROM monitor_devices WHERE instr(scope,'|')>0
            UNION SELECT scope FROM monitor_trust WHERE instr(scope,'|')>0
            UNION SELECT scope FROM monitor_alerts WHERE instr(scope,'|')>0
            """))
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                var id = reader.GetString(0);
                var parts = id.Split('|');
                if (parts.Length != 2) throw new InvalidDataException("旧监控范围格式异常，未迁移；请先备份并检查数据库。");
                legacy.Add((id, MonitorScope.Create(parts[0], parts[1])));
            }
        foreach (var group in legacy.GroupBy(s => s.Scope.Id))
        {
            var devices = ReadDevices(db, group.Key, transaction).ToDictionary(d => d.Device.Id);
            var initialized = false;
            foreach (var (id, scope) in group)
            {
                using (var state = Command(db, transaction, "SELECT initialized FROM monitor_state WHERE scope=$scope", ("$scope", id)))
                    initialized |= Convert.ToInt32(state.ExecuteScalar()) == 1;
                foreach (var old in ReadDevices(db, id, transaction))
                {
                    var history = PortHistory(old, scope.Ports);
                    var merged = old with { PortHistory = history, LastPortScope = old.LastPortScope ?? scope.Ports };
                    if (devices.TryGetValue(old.Device.Id, out var existing))
                    {
                        foreach (var (port, observation) in PortHistory(existing))
                            if (!history.TryGetValue(port, out var before) || observation.At > before.At)
                                history[port] = observation;
                        var newest = existing.LastSeen >= old.LastSeen ? existing : merged;
                        merged = newest with
                        {
                            FirstSeen = existing.FirstSeen < old.FirstSeen ? existing.FirstSeen : old.FirstSeen,
                            PortHistory = history,
                            Device = newest.Device with
                            {
                                OpenPorts = history.Count == 0 ? newest.Device.OpenPorts : history.Where(p => p.Value.Open).Select(p => p.Key).Order().ToArray(),
                                Vulnerabilities = (existing.Device.Vulnerabilities ?? []).Union(old.Device.Vulnerabilities ?? []).ToArray(),
                            },
                        };
                    }
                    devices[old.Device.Id] = merged;
                }
                using var move = Command(db, transaction, """
                    INSERT OR IGNORE INTO monitor_trust(scope,device_id)
                        SELECT $new,device_id FROM monitor_trust WHERE scope=$old;
                    UPDATE monitor_alerts SET scope=$new WHERE scope=$old;
                    DELETE FROM monitor_devices WHERE scope=$old;
                    DELETE FROM monitor_trust WHERE scope=$old;
                    DELETE FROM monitor_state WHERE scope=$old;
                    """, ("$new", group.Key), ("$old", id));
                move.ExecuteNonQuery();
            }
            foreach (var device in devices.Values) SaveDevice(db, transaction, group.Key, device);
            using var save = Command(db, transaction, """
                INSERT INTO monitor_state(scope,initialized,last_status) VALUES($scope,$init,'migrated')
                ON CONFLICT(scope) DO UPDATE SET initialized=MAX(initialized,excluded.initialized);
                """, ("$scope", group.Key), ("$init", initialized || devices.Count > 0 ? 1 : 0));
            save.ExecuteNonQuery();
        }
        transaction.Commit();
    }
}
