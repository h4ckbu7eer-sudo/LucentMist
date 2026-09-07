namespace LucentMist.Scanning.Monitoring;

internal static class MonitorIdentityMatcher
{
    internal static bool IsRandomizedMac(string? value) => MonitorDevice.NormalizeMac(value) is { } mac &&
        (Convert.ToByte(mac[..2], 16) & 2) != 0;

    internal static string? Hostname(string? value)
    {
        var name = value?.Trim().TrimEnd('.').ToLowerInvariant();
        // Name may also contain a web-page title or an explanatory placeholder.
        // Service types such as _adb._tcp are not unique device identifiers.
        if (string.IsNullOrEmpty(name) || name.Length > 253 || name.StartsWith("未知", StringComparison.Ordinal) ||
            name.StartsWith("未公开", StringComparison.Ordinal) || name.StartsWith("未广播", StringComparison.Ordinal) ||
            name is "unknown" or "localhost" || name.Contains('_') || Uri.CheckHostName(name) != UriHostNameType.Dns)
            return null;
        return name.EndsWith(".local", StringComparison.Ordinal) ? name[..^6] : name;
    }

    internal static MonitorIdentityAssociation? Match(MonitorDevice device, IReadOnlyDictionary<string, KnownDevice> old, MonitorDevice[] incoming)
    {
        old.TryGetValue(device.Id, out var previous);
        if (previous?.MergedIntoId != null || previous?.Association?.Status == "confirmed_same_device") return previous.Association;
        // Legacy rows may predate association metadata. A repeated MAC must not
        // prevent correlating an already observed rotation after an upgrade.
        var name = Hostname(device.Name);
        var candidates = name == null ? [] : old.Values.Where(d => d.Device.Id != device.Id && Hostname(d.Device.Name) == name &&
            (IsRandomizedMac(device.Mac) || IsRandomizedMac(d.Device.Mac))).ToArray();
        if (!IsRandomizedMac(device.Mac) && candidates.Length == 0 && previous?.Association == null) return null;
        var concurrent = name == null ? [] : incoming.Where(d => d.Id != device.Id && Hostname(d.Name) == name).Select(d => d.Id).ToArray();
        var roots = candidates.Select(d => Root(d.Device.Id, old)).Where(id => id != device.Id).Distinct().Order().ToArray();
        var modelConflict = MeaningfulModel(device.Model) && candidates.Any(d => MeaningfulModel(d.Device.Model) &&
            !string.Equals(device.Model?.Trim(), d.Device.Model?.Trim(), StringComparison.OrdinalIgnoreCase));
        if (roots.Length > 1 || concurrent.Length > 0 || modelConflict || previous?.Association?.Status == "identity_conflict")
            return new("identity_conflict", roots.Concat(concurrent).Concat(previous?.Association?.RelatedDeviceIds ?? [])
                .Where(id => id != device.Id).Distinct().Order().ToArray(),
                $"身份待核实：主机名/mDNS 名称 {name ?? "未取得"} 存在多设备、同时响应或型号证据冲突；不合并身份、不继承信任。");
        if (roots.Length == 1)
            return new("possible_same_device", roots, $"疑似同一设备：主机名/mDNS 名称 {name} 唯一匹配；名称未经认证，不继承信任。");
        if (previous != null && previous.Association?.Status == "identity_unconfirmed" && name != null &&
            Hostname(previous.Device.Name) == name && previous.Association.RelatedDeviceIds.Length == 0)
            return previous.Association;
        return new("identity_unconfirmed", previous?.Association?.RelatedDeviceIds ?? [], name == null
            ? "随机/本地管理 MAC：未取得可关联的主机名/mDNS 名称，身份待核实；无响应不等于未广播，不直接判为陌生设备。"
            : $"随机/本地管理 MAC：名称 {name} 未匹配已有设备，身份待核实；不直接判为陌生设备。");
    }

    internal static string Root(string id, IReadOnlyDictionary<string, KnownDevice> old)
    {
        var visited = new HashSet<string>();
        var current = id;
        while (old.TryGetValue(current, out var device))
        {
            // Corrupt/cyclic links are not evidence of a shared identity.
            if (!visited.Add(current)) return id;
            var next = device.MergedIntoId ?? (device.Association is
            { Status: "possible_same_device" or "identity_unconfirmed", RelatedDeviceIds.Length: 1 } association ? association.RelatedDeviceIds[0] : null);
            if (next == null) return current;
            if (!old.ContainsKey(next)) return id;
            current = next;
        }
        return current;
    }

    internal static string AssociationMessage(MonitorScope scope, MonitorDevice device, MonitorIdentityAssociation association,
        IReadOnlyDictionary<string, KnownDevice> old)
    {
        if (association.Status != "possible_same_device" || association.RelatedDeviceIds.Length != 1 ||
            !old.TryGetValue(association.RelatedDeviceIds[0], out var before)) return association.Evidence;
        var sameIp = before.Device.Ip == device.Ip;
        var oldArgument = sameIp || old.Values.Count(d => d.Device.Ip == before.Device.Ip) > 1 ? before.Device.Mac : before.Device.Ip;
        var newArgument = sameIp || old.Values.Any(d => d.Device.Ip == device.Ip && d.Device.Id != device.Id) ? device.Mac : device.Ip;
        return $"{device.Ip} 疑似是之前的 {before.Device.Ip}（{before.Device.Name}）换随机 MAC；" +
            $"疑似同一设备，不继承信任。运行 monitor --merge {oldArgument} {newArgument} --subnet {scope.Subnet} 确认。";
    }

    private static bool MeaningfulModel(string? value) => !string.IsNullOrWhiteSpace(value) &&
        !value.StartsWith("未知", StringComparison.Ordinal) && !value.StartsWith("未公开", StringComparison.Ordinal);
}
