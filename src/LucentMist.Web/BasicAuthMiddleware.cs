using System.Text;

namespace LucentMist.Web;

/// <summary>
/// 可选 Basic Auth，保护整个 Web UI。同时设置 LMIST_WEB_USER 与 LMIST_WEB_PASSWORD 时启用。
/// </summary>
public sealed class BasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string? _user;
    private readonly string? _password;

    public BasicAuthMiddleware(RequestDelegate next)
    {
        _next = next;
        _user = Environment.GetEnvironmentVariable("LMIST_WEB_USER");
        _password = Environment.GetEnvironmentVariable("LMIST_WEB_PASSWORD");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(_user) || string.IsNullOrWhiteSpace(_password))
        {
            await _next(context);
            return;
        }

        var header = context.Request.Headers.Authorization.ToString();
        const string prefix = "Basic ";
        if (header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[prefix.Length..].Trim()));
                var separator = decoded.IndexOf(':');
                if (separator > 0 &&
                    SafeEquals(decoded[..separator], _user) &&
                    SafeEquals(decoded[(separator + 1)..], _password))
                {
                    await _next(context);
                    return;
                }
            }
            catch (FormatException)
            {
                // 无效 Base64，按未认证处理。
            }
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Basic realm=\"LucentMist\"";
    }

    private static bool SafeEquals(string a, string b)
    {
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        return bytesA.Length == bytesB.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }
}
