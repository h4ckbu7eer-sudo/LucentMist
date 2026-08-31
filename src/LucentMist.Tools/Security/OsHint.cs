using System.Text.Json;

namespace LucentMist.Tools.Security;

public sealed record OsHint(string Family, int Confidence)
{
    public string Limitation => "TTL/端口启发式，仅辅助排序；不用于平台排除或版本确认";

    internal static OsHint? FromJson(string? json)
    {
        try
        {
            using var document = JsonDocument.Parse(json ?? "");
            var root = document.RootElement;
            var family = root.GetProperty("osFamily").GetString();
            return family is "Windows" or "Windows Server" or "Linux" or "macOS" or "FreeBSD" or "Android" or "OpenWrt"
                ? new OsHint(family, Math.Clamp(root.GetProperty("confidence").GetInt32(), 0, 100)) : null;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { return null; }
    }
}
