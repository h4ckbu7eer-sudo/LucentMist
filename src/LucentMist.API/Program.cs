using LucentMist.Agent.LLM;
using LucentMist.API.Middleware;
using LucentMist.Core.Logging;
using LucentMist.Scanning;
using Microsoft.AspNetCore.Authorization;

var startedAt = DateTime.UtcNow;
var llmProvider = (Environment.GetEnvironmentVariable("LMIST_LLM_PROVIDER") ?? "ollama")
    .Trim().ToLowerInvariant();
var llmModel = Environment.GetEnvironmentVariable("LMIST_LLM_MODEL")
    ?? LLMProviderDefaults.ModelFor(llmProvider);
var llmEndpoint = Environment.GetEnvironmentVariable("LMIST_LLM_ENDPOINT") ?? "http://localhost:11434";
var appVersion = LucentMist.Core.AppVersion.Current;
var maintenanceOwner = Environment.GetEnvironmentVariable("LMIST_DB_MAINTENANCE_OWNER") ?? "both";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddLogging(b => b.AddConsole().AddSimpleFile(
    Environment.GetEnvironmentVariable("LMIST_LOG_FILE") ?? Path.Combine("logs", "lucentmist-api.log")));

builder.WebHost.ConfigureKestrel(options =>
{
    var maxConnections = int.TryParse(
        Environment.GetEnvironmentVariable("LMIST_MAX_CONNECTIONS"),
        out var parsed) ? parsed : 512;
    options.Limits.MaxConcurrentConnections = Math.Max(16, maxConnections);
    options.Limits.MaxConcurrentUpgradedConnections = Math.Max(8, maxConnections / 4);
});

// 扫描后台任务：持久化 + 队列 + worker
builder.Services.AddSingleton(new ScanStore(
    Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db")));
builder.Services.AddSingleton(new AgentSessionStore(
    Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db")));
builder.Services.AddSingleton<ScanCoordinator>();
builder.Services.AddSingleton<IScanCoordinator>(sp =>
    sp.GetRequiredService<ScanCoordinator>());
builder.Services.AddSingleton<IScanProgressPublisher>(_ => NullScanProgressPublisher.Instance);
builder.Services.AddHostedService<ScanWorker>();
if (maintenanceOwner is "both" or "api")
    builder.Services.AddHostedService<DatabaseMaintenanceService>();

// Agent: LLM Provider + 工具注册（配置走环境变量，默认 Ollama）
builder.Services.AddHttpClient("Ollama", client =>
{
    var endpoint = Environment.GetEnvironmentVariable("LMIST_LLM_ENDPOINT") ?? "http://localhost:11434";
    client.BaseAddress = new Uri(endpoint.TrimEnd('/'));
    client.Timeout = TimeSpan.FromMinutes(5);
});
builder.Services.AddHttpClient("Claude", client =>
{
    client.BaseAddress = new Uri("https://api.anthropic.com/v1/");
    client.Timeout = TimeSpan.FromSeconds(60);
});
builder.Services.AddSingleton<LucentMist.Agent.LLM.ILLMProvider>(sp =>
{
    var lf = sp.GetRequiredService<ILoggerFactory>();
    return llmProvider switch
    {
        "claude" => new LucentMist.Agent.LLM.ClaudeProvider(
            Environment.GetEnvironmentVariable("LMIST_LLM_APIKEY") ?? "",
            llmModel,
            lf.CreateLogger<LucentMist.Agent.LLM.ClaudeProvider>(),
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("Claude")),
        _ => new LucentMist.Agent.LLM.OllamaProvider(
            llmEndpoint,
            llmModel,
            lf.CreateLogger<LucentMist.Agent.LLM.OllamaProvider>(),
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("Ollama")),
    };
});
builder.Services.AddSingleton(sp =>
{
    var lf = sp.GetRequiredService<ILoggerFactory>();
    return LucentMist.Tools.ToolRegistryFactory.CreateDefault(lf);
});

// CORS — 开发环境放开；生产仅允许 LMIST_CORS_ORIGINS 显式配置的来源
var corsOrigins = Environment.GetEnvironmentVariable("LMIST_CORS_ORIGINS");
if (builder.Environment.IsDevelopment() || !string.IsNullOrWhiteSpace(corsOrigins))
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
        {
            if (builder.Environment.IsDevelopment())
            {
                policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
            }
            else
            {
                policy.WithOrigins(
                        corsOrigins!.Split(',',
                            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            }
        });
    });
}

var app = builder.Build();

if (app.Environment.IsDevelopment() || !string.IsNullOrWhiteSpace(corsOrigins))
{
    app.UseCors();
}
app.UseMiddleware<TokenBucketRateLimitMiddleware>();
app.UseMiddleware<ApiTokenMiddleware>();
app.MapControllers();

// 健康检查
app.MapGet("/", [AllowAnonymous] () => Results.Ok(new
{
    name = "LucentMist API",
    version = appVersion,
    docs = "/api/v1/health"
}));

app.MapGet("/api/v1/health", [AllowAnonymous] () => Results.Ok(new
{
    status = "healthy",
    version = appVersion,
    uptime = $"{Math.Max(0, (int)(DateTime.UtcNow - startedAt).TotalHours)}h " +
             $"{Math.Max(0, (int)((DateTime.UtcNow - startedAt).TotalMinutes % 60))}m"
}));

app.MapGet("/api/v1/config", () => Results.Ok(new
{
    llm = new { provider = llmProvider, model = llmModel, endpoint = llmEndpoint },
    scan = new
    {
        pingTimeoutMs = 3000,
        pingConcurrency = 50,
        portTimeoutMs = 5000,
        portConcurrency = 50,
        udpTimeoutMs = 3000,
        udpConcurrency = 50,
    }
}));

var port = args.Length > 0 ? args[0] : "5050";
var bindAddress = Environment.GetEnvironmentVariable("LMIST_BIND_ADDRESS") ?? "127.0.0.1";
var aspnetUrls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
var remoteViaUrls = !string.IsNullOrWhiteSpace(aspnetUrls) &&
    aspnetUrls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Any(url => !Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
                    parsed.Host is not ("localhost" or "127.0.0.1" or "::1"));
app.Urls.Add($"http://{bindAddress}:{port}");

if ((bindAddress is not ("127.0.0.1" or "localhost" or "::1") || remoteViaUrls) &&
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_API_TOKEN")))
{
    Console.Error.WriteLine(
        "拒绝启动：API 监听非回环地址时必须设置 LMIST_API_TOKEN。");
    throw new InvalidOperationException(
        "API 监听非回环地址时必须设置 LMIST_API_TOKEN");
}

Console.WriteLine($"""
╔══════════════════════════════════════════╗
║   LucentMist API v{appVersion}                      ║
║   智能网络分析助手                       ║
╠══════════════════════════════════════════╣
║   地址: http://{bindAddress.PadRight(24)}{port.PadRight(4)}║
║   健康: /api/v1/health                   ║
║   扫描: /api/v1/scan                     ║
║   Agent: /api/v1/agent/chat              ║
╚══════════════════════════════════════════╝
""");

app.Run();

/// <summary>
/// 暴露给 WebApplicationFactory 做集成测试
/// </summary>
public partial class Program { }
