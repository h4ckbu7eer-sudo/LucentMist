namespace LucentMist.Core;

/// <summary>应用版本统一来源，避免在多个源码文件中硬编码版本字符串。</summary>
public static class AppVersion
{
    public static string Current =>
        typeof(AppVersion).Assembly.GetName().Version?.ToString(3) ?? "0.9.0";
}
