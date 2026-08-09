using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace LucentMist.API.Middleware;

/// <summary>
/// 可选 API Token 认证。设置 LMIST_API_TOKEN 后，除健康检查外所有 /api/ 请求
/// 都必须携带 Authorization: Bearer &lt;token&gt; 或 X-API-Token。
/// </summary>
public sealed class ApiTokenMiddleware
{
    private const string Prefix = "Bearer ";
    private readonly RequestDelegate _next;
    private readonly string? _token;

    public ApiTokenMiddleware(RequestDelegate next)
    {
        _next = next;
        _token = Environment.GetEnvironmentVariable("LMIST_API_TOKEN");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(_token) || IsPublic(context))
        {
            await _next(context);
            return;
        }

        var header = context.Request.Headers.Authorization.ToString();
        var candidate = header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)
            ? header[Prefix.Length..].Trim()
            : context.Request.Headers["X-API-Token"].ToString().Trim();

        if (string.IsNullOrEmpty(candidate) || !SafeEquals(candidate, _token))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new
            {
                error = new
                {
                    code = "UNAUTHORIZED",
                    message = "缺少或无效的 API Token",
                },
            });
            return;
        }

        await _next(context);
    }

    private static bool IsPublic(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() != null;

    private static bool SafeEquals(string a, string b)
    {
        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        var hashA = SHA256.HashData(bytesA);
        var hashB = SHA256.HashData(bytesB);
        return CryptographicOperations.FixedTimeEquals(hashA, hashB);
    }
}
