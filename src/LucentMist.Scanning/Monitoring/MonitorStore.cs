using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Monitoring;

/// <summary>Atomic baseline + event updates, in the same database as scan history/backup.</summary>
public sealed partial class MonitorStore
{
    private readonly string _connectionString;
    public MonitorStore(string dbPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath))!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = dbPath, Pooling = false, DefaultTimeout = 5 }.ToString();
        using var db = Open();
        using var command = db.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS monitor_state(scope TEXT PRIMARY KEY, initialized INTEGER NOT NULL DEFAULT 0 CHECK(initialized IN(0,1)), last_status TEXT NOT NULL DEFAULT 'new');
            CREATE TABLE IF NOT EXISTS monitor_devices(
                scope TEXT NOT NULL, device_id TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT, vendor TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, known_ports TEXT, state_json TEXT NOT NULL,
                PRIMARY KEY(scope,device_id));
            CREATE TABLE IF NOT EXISTS monitor_trust(scope TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY(scope,device_id));
            CREATE TABLE IF NOT EXISTS monitor_alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, occurred_at TEXT NOT NULL,
                kind TEXT NOT NULL, priority TEXT NOT NULL CHECK(priority IN('high','medium','low')), ip TEXT NOT NULL, message TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_monitor_alerts_scope ON monitor_alerts(scope,id);
            """;
        command.ExecuteNonQuery();
        MigrateLegacyScopes(db);
    }
    private SqliteConnection Open()
    {
        var db = new SqliteConnection(_connectionString);
        db.Open();
        return db;
    }
    private static SqliteCommand Command(SqliteConnection db, SqliteTransaction? transaction, string sql, params (string, object?)[] values)
    {
        var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (key, value) in values) command.Parameters.AddWithValue(key, value ?? DBNull.Value);
        return command;
    }
    private static KnownDevice[] ReadDevices(SqliteConnection db, string scope, SqliteTransaction? transaction = null)
    {
        using var command = Command(db, transaction, """
            SELECT d.state_json, EXISTS(SELECT 1 FROM monitor_trust t WHERE t.scope=d.scope AND t.device_id=d.device_id)
            FROM monitor_devices d WHERE d.scope=$scope ORDER BY d.ip
            """, ("$scope", scope));
        using var reader = command.ExecuteReader();
        var devices = new List<KnownDevice>();
        while (reader.Read()) devices.Add(JsonSerializer.Deserialize<KnownDevice>(reader.GetString(0))! with { Trusted = reader.GetBoolean(1) });
        return devices.ToArray();
    }
    public KnownDevice[] ListDevices(MonitorScope scope)
    {
        using var db = Open();
        return ReadDevices(db, scope.Id);
    }
    public string Trust(MonitorScope scope, string ipOrMac)
    {
        using var db = Open();
        using var transaction = db.BeginTransaction();
        var mac = MonitorDevice.NormalizeMac(ipOrMac);
        if (mac == null)
        {
            if (!IPAddress.TryParse(ipOrMac, out var address)) throw new ArgumentException("请提供有效 IP 或 MAC。");
            var candidates = ReadDevices(db, scope.Id, transaction).Where(d => d.Present && d.IdentityConfirmed && d.Device.Ip == address.ToString()).ToArray();
            if (candidates.Length != 1 || (mac = MonitorDevice.NormalizeMac(candidates[0].Device.Mac)) == null)
                throw new ArgumentException("该 IP 没有唯一已观测 MAC；请先扫描，或直接指定设备 MAC。不会永久信任可复用的 IP。");
        }
        using var command = Command(db, transaction, "INSERT OR IGNORE INTO monitor_trust(scope,device_id) VALUES($scope,$id)",
            ("$scope", scope.Id), ("$id", "mac:" + mac));
        command.ExecuteNonQuery();
        transaction.Commit();
        return mac;
    }
    public MonitorAlert[] ListAlerts(MonitorScope scope, int limit = 100)
    {
        using var db = Open();
        // Old releases stored coverage status as events. Keep the historical rows,
        // but do not let them crowd out actual changes in the alert view.
        using var command = Command(db, null, "SELECT id,occurred_at,kind,priority,ip,message FROM monitor_alerts WHERE scope=$scope AND kind!='analysis_incomplete' ORDER BY id DESC LIMIT $limit",
            ("$scope", scope.Id), ("$limit", Math.Clamp(limit, 1, 1000)));
        using var reader = command.ExecuteReader();
        var alerts = new List<MonitorAlert>();
        while (reader.Read()) alerts.Add(new(reader.GetInt64(0), DateTimeOffset.Parse(reader.GetString(1)), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)));
        return alerts.ToArray();
    }
    public MonitorUpdate Apply(MonitorScope scope, NetworkSnapshot snapshot, DateTimeOffset now)
    {
        using var db = Open();
        using var transaction = db.BeginTransaction();
        using (var create = Command(db, transaction, "INSERT OR IGNORE INTO monitor_state(scope) VALUES($scope)", ("$scope", scope.Id))) create.ExecuteNonQuery();
        bool initialized; string lastStatus;
        using (var state = Command(db, transaction, "SELECT initialized,last_status FROM monitor_state WHERE scope=$scope", ("$scope", scope.Id)))
        using (var reader = state.ExecuteReader()) { reader.Read(); initialized = reader.GetBoolean(0); lastStatus = reader.GetString(1); }
        var old = ReadDevices(db, scope.Id, transaction).ToDictionary(d => d.Device.Id);
        var scannedPorts = scope.Ports.Split(',').Select(int.Parse).ToHashSet();
        var alerts = new List<MonitorAlert>();
        var unconfirmedIdentities = new HashSet<string>();
        var identityAssociations = new Dictionary<string, MonitorIdentityAssociation>();
        var duplicateIdentity = snapshot.Devices.GroupBy(d => d.Id).Any(g => g.Count() > 1);
        var uncertain = !snapshot.DiscoverySucceeded || snapshot.Devices.Length == 0 || duplicateIdentity;
        if (uncertain)
        {
            if (lastStatus != "uncertain") Alert("monitor_unavailable", "low", "", duplicateIdentity
                ? "本轮多个地址报告同一设备标识，身份存在歧义；保留基线，请核对代理 ARP/MAC。"
                : "本轮发现失败或整个网段无响应；保留基线，不报所有设备消失。" + snapshot.Error);
        }
        else
        {
            var incoming = snapshot.Devices.GroupBy(d => d.Id).ToDictionary(g => g.Key, g => g.First());
            foreach (var device in incoming.Values)
                if (MonitorIdentityMatcher.Match(device, old, snapshot.Devices) is { } association)
                    identityAssociations[device.Id] = association;
            var relatedIds = identityAssociations.Values.SelectMany(a => a.RelatedDeviceIds).ToHashSet();
            foreach (var id in incoming.Keys.Where(old.ContainsKey)) relatedIds.Add(MonitorIdentityMatcher.Root(id, old));
            // Keep old MAC rows and their trust/port baselines separate. An absent
            // alias is not proof that a physical device disappeared during rotation.
            foreach (var previous in old.Values.Where(d => !incoming.ContainsKey(d.Device.Id) &&
                (relatedIds.Contains(d.Device.Id) || relatedIds.Contains(MonitorIdentityMatcher.Root(d.Device.Id, old)))))
            {
                if (previous.MergedIntoId == null) unconfirmedIdentities.Add(previous.Device.Id);
                Save(previous with { Present = false, IdentityConfirmed = false, LastPortScanSucceeded = false });
            }
            foreach (var (id, device) in incoming)
            {
                // Missing ARP/neighbor evidence cannot prove either a new device or
                // the disappearance of the previously observed MAC at this IP.
                // Do not transfer trust or fresh port data across an unverified identity.
                if (MonitorDevice.NormalizeMac(device.Mac) == null)
                {
                    var candidates = old.Values.Where(d => d.Device.Ip == device.Ip &&
                        MonitorDevice.NormalizeMac(d.Device.Mac) != null && !incoming.ContainsKey(d.Device.Id)).ToArray();
                    if (candidates.Length > 0)
                    {
                        if (candidates.Any(d => d.IdentityConfirmed))
                            Alert("identity_unconfirmed", "low", device.Ip, "该 IP 本轮有响应但未取得 MAC，无法确认是否原设备；不判定新设备或原设备消失，不继承信任，保留历史基线。其它设备继续正常比对。");
                        foreach (var candidate in candidates)
                        {
                            unconfirmedIdentities.Add(candidate.Device.Id);
                            Save(candidate with { IdentityConfirmed = false, LastPortScanSucceeded = false });
                        }
                        continue;
                    }
                }
                old.TryGetValue(id, out var previous);
                identityAssociations.TryGetValue(id, out var identityAssociation);
                var history = PortHistory(previous);
                using var trust = Command(db, transaction, "SELECT COUNT(*) FROM monitor_trust WHERE scope=$scope AND device_id=$id", ("$scope", scope.Id), ("$id", id));
                var trusted = Convert.ToInt32(trust.ExecuteScalar()) > 0;
                if (initialized && previous == null && !trusted && identityAssociation == null)
                    Alert("new_device", "high", device.Ip, "发现新的未信任设备（可能陌生设备）；核对后使用 monitor --trust 标记。MAC 可伪造/随机化，无 MAC 时仅按 IP 区分，不是入侵确认。");
                if (initialized && identityAssociation != null && (previous?.Association?.Status != identityAssociation.Status ||
                    !identityAssociation.RelatedDeviceIds.SequenceEqual(previous.Association.RelatedDeviceIds)))
                    Alert("identity_association", identityAssociation.Status is "identity_conflict" or "possible_same_device" ? "medium" : "low", device.Ip,
                        MonitorIdentityMatcher.AssociationMessage(scope, device, identityAssociation, old));
                if (previous != null)
                {
                    if (!previous.Present) Alert("device_returned", "low", device.Ip, "已知设备重新被观测到。");
                    if (previous.Device.Ip != device.Ip) Alert("ip_changed", "low", device.Ip, $"同一 MAC 的 IP 从 {previous.Device.Ip} 变为 {device.Ip}，不是新设备。");
                    if (device.OpenPorts != null)
                    {
                        foreach (var port in scannedPorts.Where(history.ContainsKey))
                        {
                            var isOpen = device.OpenPorts.Contains(port);
                            if (isOpen && !history[port].Open) Alert("port_added", "medium", device.Ip, $"新增可连接 TCP 端口 {port}；核对是否启用了新服务，不据此认定被入侵。");
                            if (!isOpen && history[port].Open) Alert("port_not_observed", "low", device.Ip, $"TCP 端口 {port} 本次未连接成功；可能关闭、过滤或暂时不可达，不能确定已关闭。");
                        }
                    }
                    if (Meaningful(device.Vendor) && Meaningful(previous.Device.Vendor) && device.Vendor != previous.Device.Vendor)
                        Alert("vendor_changed", "medium", device.Ip, $"厂商线索变化：{previous.Device.Vendor} → {device.Vendor}，需核对设备。");
                    foreach (var (port, service) in device.Services ?? [])
                        if (Meaningful(service) && previous.Device.Services?.TryGetValue(port, out var before) == true && Meaningful(before) && before != service)
                            Alert("service_changed", "medium", device.Ip, $"端口 {port} 的服务证据变化：{before} → {service}。");
                }
                foreach (var risk in (device.Vulnerabilities ?? []).Except(previous?.Device.Vulnerabilities ?? []))
                    Alert("vulnerability_candidate", "high", device.Ip, $"新增漏洞候选 {risk}；候选不是确认漏洞，需核对受影响版本及厂商补丁。");
                if (device.OpenPorts != null)
                    foreach (var port in scannedPorts) history[port] = new(device.OpenPorts.Contains(port), now);
                var retained = device with
                {
                    Vendor = Meaningful(device.Vendor) ? device.Vendor : previous?.Device.Vendor ?? device.Vendor,
                    Name = Meaningful(device.Name) ? device.Name : previous?.Device.Name ?? device.Name,
                    Model = Meaningful(device.Model) ? device.Model : previous?.Device.Model ?? device.Model,
                    DhcpHostname = device.DhcpObserved != null ? device.DhcpHostname : previous?.Device.DhcpHostname,
                    DhcpVendorClass = device.DhcpObserved != null ? device.DhcpVendorClass : previous?.Device.DhcpVendorClass,
                    DhcpObserved = device.DhcpObserved ?? previous?.Device.DhcpObserved,
                    DhcpSourceMode = device.DhcpSourceMode ?? previous?.Device.DhcpSourceMode,
                    OpenPorts = history.Count > 0 ? history.Where(p => p.Value.Open).Select(p => p.Key).Order().ToArray() : previous?.Device.OpenPorts,
                    Services = (previous?.Device.Services ?? []).Concat(device.Services ?? []).GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.Last().Value),
                    Vulnerabilities = (previous?.Device.Vulnerabilities ?? []).Union(device.Vulnerabilities ?? []).ToArray(),
                };
                Save(new(retained, previous?.FirstSeen ?? now, now, true, trusted,
                    device.OpenPorts != null ? now : previous?.PortsObservedAt, device.OpenPorts != null,
                    PortHistory: history, LastPortScope: device.OpenPorts != null ? scope.Ports : previous?.LastPortScope,
                    Association: identityAssociation, MergedIntoId: previous?.MergedIntoId));
            }
            foreach (var previous in old.Values.Where(d => d.Present && !incoming.ContainsKey(d.Device.Id) && !unconfirmedIdentities.Contains(d.Device.Id)))
            {
                if (previous.MergedIntoId == null)
                    Alert("missing_device", "low", previous.Device.Ip, "本轮未观测到已知设备；可能休眠、离线或被过滤，不等于确认断开。");
                Save(previous with { Present = false });
            }
            if (snapshot.Devices.Any(d => d.OpenPorts == null) && lastStatus != "partial")
                Alert("port_scan_incomplete", "low", "", "部分设备端口扫描失败，保留其上次端口基线；不能据此认定端口关闭。");
        }
        var status = uncertain ? "uncertain" : unconfirmedIdentities.Count > 0 || identityAssociations.Values.Any(a => a.Status != "confirmed_same_device") || snapshot.Devices.Any(d => d.OpenPorts == null || d.Warnings?.Length > 0) ? "partial" : "completed";
        using (var update = Command(db, transaction, "UPDATE monitor_state SET initialized=$init,last_status=$status WHERE scope=$scope",
            ("$init", initialized || !uncertain ? 1 : 0), ("$status", status), ("$scope", scope.Id))) update.ExecuteNonQuery();
        transaction.Commit();
        return new(!initialized && !uncertain, !uncertain, ListDevices(scope), alerts.ToArray(),
            uncertain ? "本轮无法确认，基线未覆盖" : $"观测 {snapshot.Devices.Length} 台设备，产生 {alerts.Count} 条告警；{status}");

        void Save(KnownDevice device)
        {
            SaveDevice(db, transaction, scope.Id, device);
        }
        void Alert(string kind, string priority, string ip, string message)
        {
            using var command = Command(db, transaction, "INSERT INTO monitor_alerts(scope,occurred_at,kind,priority,ip,message) VALUES($scope,$at,$kind,$priority,$ip,$message); SELECT last_insert_rowid();",
                ("$scope", scope.Id), ("$at", now.ToString("O")), ("$kind", kind), ("$priority", priority), ("$ip", ip), ("$message", message));
            alerts.Add(new(Convert.ToInt64(command.ExecuteScalar()), now, kind, priority, ip, message));
        }
    }
    private static void SaveDevice(SqliteConnection db, SqliteTransaction transaction, string scope, KnownDevice device)
    {
        using var command = Command(db, transaction, """
            INSERT INTO monitor_devices(scope,device_id,ip,mac,vendor,first_seen,last_seen,known_ports,state_json)
            VALUES($scope,$id,$ip,$mac,$vendor,$first,$last,$ports,$json)
            ON CONFLICT(scope,device_id) DO UPDATE SET ip=excluded.ip,mac=excluded.mac,vendor=excluded.vendor,
                first_seen=excluded.first_seen,last_seen=excluded.last_seen,known_ports=excluded.known_ports,state_json=excluded.state_json
            """, ("$scope", scope), ("$id", device.Device.Id), ("$ip", device.Device.Ip), ("$mac", device.Device.Mac), ("$vendor", device.Device.Vendor),
            ("$first", device.FirstSeen.ToString("O")), ("$last", device.LastSeen.ToString("O")), ("$ports", JsonSerializer.Serialize(device.Device.OpenPorts)), ("$json", JsonSerializer.Serialize(device)));
        command.ExecuteNonQuery();
    }
    private static Dictionary<int, MonitorPortObservation> PortHistory(KnownDevice? device, string? legacyPorts = null)
    {
        if (device?.PortHistory != null) return new(device.PortHistory);
        var result = new Dictionary<int, MonitorPortObservation>();
        if (device?.Device.OpenPorts == null || device.PortsObservedAt == null) return result;
        // With no coverage evidence we can retain positive observations only.
        var ports = legacyPorts ?? device.LastPortScope;
        foreach (var port in ports == null ? device.Device.OpenPorts : ports.Split(',').Select(int.Parse))
            result[port] = new(device.Device.OpenPorts.Contains(port), device.PortsObservedAt.Value);
        return result;
    }
    private static bool Meaningful(string? value) => !string.IsNullOrWhiteSpace(value) &&
        !value.StartsWith("未知", StringComparison.Ordinal) && !value.StartsWith("本地管理", StringComparison.Ordinal);
}
