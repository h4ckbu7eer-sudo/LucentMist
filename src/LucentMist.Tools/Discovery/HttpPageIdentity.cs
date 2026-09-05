using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace LucentMist.Tools.Discovery;

/// <summary>Unauthenticated page identity, separate from service/firmware versions and CPEs.</summary>
public sealed record HttpPageIdentity(
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("vendor")] string? Vendor,
    [property: JsonPropertyName("model")] string? Model,
    [property: JsonPropertyName("generator")] string? Generator,
    [property: JsonPropertyName("evidence")] string Evidence)
{
    internal static HttpPageIdentity Read(string html, string? authenticate = null)
    {
        var title = Clean(Match(html, @"<title\b[^>]*>([^<]{1,512})</title\s*>"));
        string? vendor = null, model = null;
        // Adapted from Recog http_wwwauth.xml: ZTE CPE, ZXHN and ZXV (BSD-2-Clause).
        var realm = Match(authenticate ?? "", "^(?:Basic|Digest).*realm=\"([^\"]{1,128})\"");
        if (realm != null)
        {
            if (realm.Equals("cpe@zte.com", StringComparison.OrdinalIgnoreCase)) vendor = "ZTE";
            else if (Regex.IsMatch(realm, @"^(?:ZXHN \S+|ZXV\S* \S+)$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            { vendor = "ZTE"; model = Clean(realm); }
        }
        // Explicit branding/model strings in the title; arbitrary body mentions are not identity.
        if (title != null)
        {
            if (title.Contains("中兴", StringComparison.Ordinal) || Regex.IsMatch(title, @"\b(?:ZTE|ZXHN|ZXDSL|ZXV10)\b", RegexOptions.IgnoreCase)) vendor ??= "ZTE";
            if (vendor == "ZTE") model ??= Match(title, @"\b((?:ZXHN|ZXDSL|ZXV10)[ _-][A-Z0-9][A-Z0-9._-]{1,24})\b");
            if (vendor == "ZTE") model ??= Match(title, @"\bZTE\s+(F[0-9]{2,4}[A-Z0-9-]*)\b");
        }
        var generator = Match(html, "<meta\\s+name=[\"']generator[\"']\\s+content=[\"']([^\"']{1,128})[\"']");
        return new(title, vendor, model, Clean(generator),
            "来自 GET / 标题/声明或 WWW-Authenticate realm，未经认证；网页名称不是硬件型号，型号不是固件版本，不能据此确认 CVE。未保存正文、Cookie 或认证数据。");
    }

    private static string? Match(string text, string pattern)
    {
        var match = Regex.Match(text, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        return match.Success ? match.Groups[1].Value : null;
    }

    private static string? Clean(string? value)
    {
        if (value == null) return null;
        value = WebUtility.HtmlDecode(value);
        value = new string(value.Where(c => !char.IsControl(c)).Take(160).ToArray()).Trim();
        return value.Length == 0 ? null : value;
    }
}
