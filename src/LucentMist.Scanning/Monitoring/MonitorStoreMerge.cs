using System.Net;

namespace LucentMist.Scanning.Monitoring;

public sealed partial class MonitorStore
{
    public KnownDevice Merge(MonitorScope scope, string oldIdentity, string newIdentity, DateTimeOffset now)
    {
        using var db = Open();
        using var transaction = db.BeginTransaction();
        var devices = ReadDevices(db, scope.Id, transaction).ToDictionary(d => d.Device.Id);
        var source = Resolve(oldIdentity);
        var target = Resolve(newIdentity);
        if (source.Device.Id == target.Device.Id) throw new ArgumentException("旧、新身份相同，无需合并。");
        if (target.MergedIntoId != null) throw new ArgumentException("新身份已被合并，请指定当前设备的 IP/MAC。");
        if (!target.Present || !target.IdentityConfirmed) throw new ArgumentException("新身份没有当前有效观测，请先扫描再确认合并。");
        if (MonitorDevice.NormalizeMac(source.Device.Mac) == null || MonitorDevice.NormalizeMac(target.Device.Mac) == null)
            throw new ArgumentException("两端都需要已观测 MAC；不能把可复用的 IP 永久合并。");
        var sourceRoot = ConfirmedRoot(source.Device.Id);
        if (sourceRoot == target.Device.Id) return target;
        source = devices[sourceRoot];
        var sourceGroup = devices.Values.Where(d => ConfirmedRoot(d.Device.Id) == sourceRoot).ToArray();
        if (sourceGroup.Any(d => d.Present)) throw new ArgumentException("旧身份仍被观测到，可能是两台设备；先重新扫描核实，不能合并同时在线的身份。");
        var group = sourceGroup.Concat(devices.Values.Where(d => ConfirmedRoot(d.Device.Id) == target.Device.Id)).ToArray();
        var history = new Dictionary<int, MonitorPortObservation>();
        // Later per-port evidence wins; the destination wins timestamp ties.
        foreach (var item in group.OrderBy(d => d.Device.Id == target.Device.Id))
            foreach (var (port, observation) in PortHistory(item))
                if (!history.TryGetValue(port, out var existing) || observation.At >= existing.At) history[port] = observation;
        var latestPorts = group.OrderByDescending(d => d.PortsObservedAt).First();
        var message = $"用户显式确认合并：{source.Device.Ip} → {target.Device.Ip}；信任与历史已迁移，旧身份归档保留。";
        var merged = target with
        {
            FirstSeen = group.Min(d => d.FirstSeen),
            Trusted = group.Any(d => d.Trusted),
            PortHistory = history,
            PortsObservedAt = latestPorts.PortsObservedAt,
            LastPortScope = latestPorts.LastPortScope,
            Association = new("confirmed_same_device", group.Where(d => d.Device.Id != target.Device.Id).Select(d => d.Device.Id).Distinct().ToArray(), message),
            Device = target.Device with
            {
                OpenPorts = history.Count == 0 ? target.Device.OpenPorts : history.Where(p => p.Value.Open).Select(p => p.Key).Order().ToArray(),
                Services = group.OrderBy(d => d.LastSeen).SelectMany(d => d.Device.Services ?? []).GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.Last().Value),
                Vulnerabilities = group.SelectMany(d => d.Device.Vulnerabilities ?? []).Distinct().ToArray(),
            },
        };
        foreach (var item in group.Where(d => d.Device.Id != target.Device.Id))
            SaveDevice(db, transaction, scope.Id, item with { MergedIntoId = target.Device.Id, Present = false, IdentityConfirmed = false });
        SaveDevice(db, transaction, scope.Id, merged);
        if (merged.Trusted)
        {
            foreach (var member in group)
            {
                using var trust = Command(db, transaction, "INSERT OR IGNORE INTO monitor_trust(scope,device_id) VALUES($scope,$id)",
                    ("$scope", scope.Id), ("$id", member.Device.Id));
                trust.ExecuteNonQuery();
            }
        }
        using (var alert = Command(db, transaction, "INSERT INTO monitor_alerts(scope,occurred_at,kind,priority,ip,message) VALUES($scope,$at,'identity_merged','medium',$ip,$message)",
            ("$scope", scope.Id), ("$at", now.ToString("O")), ("$ip", target.Device.Ip), ("$message", message))) alert.ExecuteNonQuery();
        transaction.Commit();
        return merged;

        KnownDevice Resolve(string input)
        {
            var mac = MonitorDevice.NormalizeMac(input);
            if (mac != null && devices.TryGetValue("mac:" + mac, out var byMac)) return byMac;
            if (mac == null && IPAddress.TryParse(input, out var ip))
            {
                var matches = devices.Values.Where(d => d.Device.Ip == ip.ToString()).ToArray();
                if (matches.Length == 1) return matches[0];
                if (matches.Length > 1) throw new ArgumentException($"IP {ip} 对应多条历史 MAC，请明确指定 MAC 后合并。");
            }
            throw new ArgumentException($"当前网段未找到身份 {input}，请先用 --devices 核对完整 IP/MAC。");
        }
        string ConfirmedRoot(string id)
        {
            var visited = new HashSet<string>();
            while (devices.TryGetValue(id, out var item) && item.MergedIntoId is { } next)
            {
                if (!visited.Add(id) || !devices.ContainsKey(next)) throw new InvalidDataException("合并历史有循环或缺失记录，未执行合并；请检查备份。");
                id = next;
            }
            return id;
        }
    }
}
