using System.Numerics;
using System.Text.RegularExpressions;

namespace LucentMist.Tools.Security;

/// <summary>Upstream numeric releases (including OpenSSH p suffix), not distro package versions.</summary>
public sealed record AffectedVersionRange(string Introduced, string Fixed)
{
    public bool Contains(string version) => Compare(version, Introduced) is >= 0
        && Compare(version, Fixed) is < 0;

    internal static int? Compare(string left, string right)
    {
        static BigInteger[]? Parse(string value) => Regex.IsMatch(value, @"^\d+(?:\.\d+)*(?:p\d+)?$", RegexOptions.IgnoreCase)
            ? Regex.Matches(value, @"\d+").Select(m => BigInteger.Parse(m.Value, System.Globalization.CultureInfo.InvariantCulture)).ToArray()
            : null;
        var a = Parse(left);
        var b = Parse(right);
        if (a == null || b == null) return null;
        for (var i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            var comparison = (i < a.Length ? a[i] : BigInteger.Zero).CompareTo(i < b.Length ? b[i] : BigInteger.Zero);
            if (comparison != 0) return comparison;
        }
        return 0;
    }
}
