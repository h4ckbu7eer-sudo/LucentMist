using LucentMist.API.Middleware;
using LucentMist.Scanning;
using Microsoft.AspNetCore.Authorization;

var startedAt = DateTime.UtcNow;
var llmProvider = Environment.GetEnvironmentVariable("LMIST_LLM_PROVIDER") ?? "ollama";
var llmModel = Environment.GetEnvironmentVariable("LMIST_LLM_MODEL") ?? "qwen2.5:7b";
var llmEndpoint = Environment.GetEnvironmentVariable("LMIST_LLM_ENDPOINT") ?? "http://localhost:11434";
var appVersion = LucentMist.Core.AppVersion.Current;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddLogging(b => b.AddConsole());

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
    var provider = Environment.GetEnvironmentVariable("LMIST_LLM_PROVIDER") ?? "ollama";
    var model = Environment.GetEnvironmentVariable("LMIST_LLM_MODEL") ?? "qwen2.5:7b";
    var endpoint = Environment.GetEnvironmentVariable("LMIST_LLM_ENDPOINT") ?? "http://localhost:11434";
    var lf = sp.GetRequiredService<ILoggerFactory>();
    return provider.ToLower() switch
    {
        "claude" => new LucentMist.Agent.LLM.ClaudeProvider(
            Environment.GetEnvironmentVariable("LMIST_LLM_APIKEY") ?? "",
            model,
            lf.CreateLogger<LucentMist.Agent.LLM.ClaudeProvider>(),
            sp.GetRequiredService<IHttpClientFactory>().CreateClient("Claude")),
        _ => new LucentMist.Agent.LLM.OllamaProvider(
            endpoint,
            model,
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
        portTimeoutMs = 2000,
        portConcurrency = 100,
        udpTimeoutMs = 3000,
        udpConcurrency = 20,
    }
}));

var port = args.Length > 0 ? args[0] : "5050";
var bindAddress = Environment.GetEnvironmentVariable("LMIST_BIND_ADDRESS") ?? "127.0.0.1";
app.Urls.Add($"http://{bindAddress}:{port}");

if (bindAddress is not ("127.0.0.1" or "localhost" or "::1") &&
    string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_API_TOKEN")))
{
    Console.Error.WriteLine("WARNING: API 正在监听非回环地址但未设置 LMIST_API_TOKEN，生产环境必须启用认证。");
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
