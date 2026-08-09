namespace LucentMist.API.Middleware;

/// <summary>
/// 进程内令牌桶限流，保护 Agent/Scan 后端不被 CLI/Web 并发调用打垮。
/// 可通过 LMIST_RATE_LIMIT_RPS 与 LMIST_RATE_LIMIT_BURST 覆盖。
/// </summary>
public sealed class TokenBucketRateLimitMiddleware
{
    private static readonly string[] LimitedPaths =
    [
        "/api/v1/agent/chat",
        "/api/v1/scan",
    ];

    private readonly RequestDelegate _next;
    private readonly double _rps;
    private readonly int _burst;
    private readonly object _lock = new();
    private double _tokens;
    private DateTime _lastRefill = DateTime.UtcNow;

    public TokenBucketRateLimitMiddleware(RequestDelegate next)
    {
        _next = next;
        _rps = ParsePositiveDouble("LMIST_RATE_LIMIT_RPS", 5);
        _burst = (int)ParsePositiveDouble("LMIST_RATE_LIMIT_BURST", 10);
        _tokens = _burst;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        if (!LimitedPaths.Any(p =>
                path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        var limited = false;
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastRefill).TotalSeconds;
            _tokens = Math.Min(_burst, _tokens + elapsed * _rps);
            _lastRefill = now;

            if (_tokens < 1)
                limited = true;
            else
                _tokens -= 1;
        }

        if (limited)
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new
            {
                error = new
                {
                    code = "RATE_LIMITED",
                    message = "请求过于频繁，请稍后重试",
                },
            });
            return;
        }

        await _next(context);
    }

    private static double ParsePositiveDouble(string name, double fallback)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        return double.TryParse(raw, out var value) && value > 0
            ? value
            : fallback;
    }
}
