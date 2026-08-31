using System.Text;

namespace LucentMist.Tools.Discovery;

/// <summary>Offline IEEE MA-L/OUI lookup. A full IEEE CSV may be supplied by LMIST_OUI_DB_PATH.</summary>
public sealed class OuiDatabase
{
    private readonly Dictionary<string, string> _vendors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["000C29"] = "VMware, Inc.",
        ["00155D"] = "Microsoft Corporation",
        // IEEE MA-L snapshot verified 2026-09-01; these are vendor clues, not models.
        ["00179A"] = "D-Link Corporation",
        ["001B11"] = "D-Link Corporation",
        ["001B21"] = "Intel Corporate",
        ["001C42"] = "Parallels, Inc.",
        ["001E10"] = "Huawei Technologies",
        ["0024E8"] = "Dell Inc.",
        ["0026BB"] = "Apple, Inc.",
        ["0C9D92"] = "ASUSTek COMPUTER INC.",
        ["18D6C7"] = "TP-Link Technologies Co., Ltd.",
        ["286C07"] = "XIAOMI Electronics,CO.,LTD",
        ["3C846A"] = "TP-Link Technologies Co., Ltd.",
        ["5CC5D4"] = "Intel Corporate",
        ["7C7D21"] = "ZTE Corporation",
        ["7C10C9"] = "Cisco Systems, Inc",
        ["B827EB"] = "Raspberry Pi Foundation",
        ["D850E6"] = "ASUSTek COMPUTER INC.",
        ["E45F01"] = "Raspberry Pi Trading Ltd",
        ["F4F5D8"] = "Google, Inc.",
    };

    public OuiDatabase(string? csvPath = null)
    {
        var candidates = new[]
        {
            csvPath,
            Environment.GetEnvironmentVariable("LMIST_OUI_DB_PATH"),
            Path.Combine(AppContext.BaseDirectory, "data", "oui.csv"),
            Path.Combine(AppContext.BaseDirectory, "data", "nmap-mac-prefixes"),
            OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Nmap", "nmap-mac-prefixes")
                : "/usr/share/nmap/nmap-mac-prefixes",
        };
        var path = candidates.FirstOrDefault(candidate =>
            !string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate));
        if (path == null) return;
        var lines = File.ReadLines(path);
        if (Path.GetFileName(path).Contains("nmap-mac-prefixes", StringComparison.OrdinalIgnoreCase))
            LoadNmapPrefixes(lines);
        else
            LoadCsv(lines);
    }

    internal void LoadNmapPrefixes(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            var value = line.Trim();
            if (value.Length < 8 || value.StartsWith('#')) continue;
            var separator = value.IndexOfAny([' ', '\t']);
            if (separator <= 0) continue;
            var assignment = new string(value[..separator].Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            var vendor = value[(separator + 1)..].Trim();
            if (assignment.Length == 6 && vendor.Length > 0) _vendors[assignment] = vendor;
        }
    }

    public string? Lookup(string? macAddress)
    {
        var normalized = NormalizeMac(macAddress);
        if (normalized == null) return null;
        if ((Convert.ToByte(normalized[..2], 16) & 0x02) != 0)
            return "本地管理/随机 MAC（无法由 OUI 确认厂商）";
        return _vendors.GetValueOrDefault(normalized[..6]);
    }

    internal void LoadCsv(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            var fields = ParseCsvLine(line);
            if (fields.Count < 3 || fields[0].Equals("Registry", StringComparison.OrdinalIgnoreCase)) continue;
            var assignment = new string(fields[1].Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
            if (assignment.Length == 6 && !string.IsNullOrWhiteSpace(fields[2])) _vendors[assignment] = fields[2].Trim();
        }
    }

    internal static string? NormalizeMac(string? macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress)) return null;
        var normalized = new string(macAddress.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        return normalized.Length == 12 ? normalized : null;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var value = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { value.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (ch == ',' && !quoted) { fields.Add(value.ToString()); value.Clear(); }
            else value.Append(ch);
        }
        fields.Add(value.ToString());
        return fields;
    }
}
