using LucentMist.Scanning.Monitoring;

namespace LucentMist.CLI;

internal sealed record MonitorDeviceRow(KnownDevice Item, string Label, KnownDevice[] Replaced);

internal static class MonitorDevicePresentation
{
    internal static MonitorDeviceRow[] Rows(KnownDevice[] devices)
    {
        var byId = devices.ToDictionary(d => d.Device.Id);
        var rows = new List<MonitorDeviceRow>();
        foreach (var group in devices.GroupBy(d => ConfirmedRoot(d.Device.Id)))
        {
            var canonical = byId[group.Key];
            var live = group.Where(d => d.Present).ToArray();
            // A confirmed historical merge cannot hide two simultaneously observed identities.
            if (live.Length > 1)
            {
                rows.AddRange(live.Select(d => new MonitorDeviceRow(d, "身份待核实：已合并的旧、新 MAC 同时响应", [])));
                continue;
            }
            var current = live.SingleOrDefault() ?? canonical;
            var replaced = group.Where(d => d.Device.Id != current.Device.Id).ToArray();
            if (replaced.Length > 0)
            {
                var history = group.SelectMany(d => d.PortHistory ?? []).GroupBy(p => p.Key)
                    .ToDictionary(g => g.Key, g => g.MaxBy(p => p.Value.At).Value);
                var latest = group.OrderByDescending(d => d.PortsObservedAt).First();
                current = current with
                {
                    FirstSeen = canonical.FirstSeen,
                    Association = canonical.Association,
                    PortHistory = history,
                    PortsObservedAt = latest.PortsObservedAt,
                    LastPortScope = latest.LastPortScope,
                    Device = current.Device with { OpenPorts = history.Count == 0 ? current.Device.OpenPorts : history.Where(p => p.Value.Open).Select(p => p.Key).Order().ToArray() },
                };
            }
            rows.Add(new(current, replaced.Length == 0 ? "" : "已确认 = 旧 " + string.Join("、", replaced.Select(d => d.Device.Ip).Distinct()), replaced));
        }
        var hidden = new HashSet<string>();
        foreach (var current in rows.Where(r => r.Item.Present && r.Item.Association?.Status == "possible_same_device").ToArray())
        {
            var ids = current.Item.Association!.RelatedDeviceIds;
            var replaced = rows.Where(r => !r.Item.Present && (ids.Contains(r.Item.Device.Id) ||
                r.Item.Association?.Status == "possible_same_device" && r.Item.Association.RelatedDeviceIds.Intersect(ids).Any()))
                .Select(r => r.Item).ToArray();
            if (replaced.Length == 0) continue;
            var index = rows.IndexOf(current);
            rows[index] = current with
            {
                Label = "⚠ 疑似 = 旧 " + string.Join("、", replaced.Select(d => d.Device.Ip).Distinct()) + "（MAC 随机化待确认）",
                Replaced = replaced,
            };
            foreach (var item in replaced) hidden.Add(item.Device.Id);
        }
        return rows.Where(r => !hidden.Contains(r.Item.Device.Id)).ToArray();

        string ConfirmedRoot(string id)
        {
            var visited = new HashSet<string>();
            while (byId[id].MergedIntoId is { } next)
            {
                if (!visited.Add(id) || !byId.ContainsKey(next)) throw new InvalidDataException("合并历史异常，请核对数据库备份；未隐藏异常设备。");
                id = next;
            }
            return id;
        }
    }
}
