using LucentMist.API.Middleware;
using LucentMist.Scanning;

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
    var registry = new LucentMist.Tools.ToolRegistry();
    registry.Register(new LucentMist.Tools.Scanning.PingScanTool(lf.CreateLogger<LucentMist.Tools.Scanning.PingScanTool>()));
    registry.Register(new LucentMist.Tools.Scanning.PortScanTool(lf.CreateLogger<LucentMist.Tools.Scanning.PortScanTool>()));
    registry.Register(new LucentMist.Tools.Scanning.ServiceIdentifyTool(lf.CreateLogger<LucentMist.Tools.Scanning.ServiceIdentifyTool>()));
    registry.Register(new LucentMist.Tools.Scanning.DeviceQueryTool(lf.CreateLogger<LucentMist.Tools.Scanning.DeviceQueryTool>(), new List<LucentMist.Core.Models.Device>()));
    return registry;
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
    app.UseCors();
app.UseMiddleware<TokenBucketRateLimitMiddleware>();
app.MapControllers();

// 健康检查
app.MapGet("/", () => Results.Ok(new
{
    name = "LucentMist API",
    version = "0.9.0",
    docs = "/api/v1/health"
}));

app.MapGet("/api/v1/health", () => Results.Ok(new
{
    status = "healthy",
    version = "0.9.0",
    uptime = "0h 0m"
}));

app.MapGet("/api/v1/config", () => Results.Ok(new
{
    llm = new { provider = "ollama", model = "qwen2.5:7b" },
    scan = new { defaultTimeoutMs = 5000, maxConcurrency = 100 }
}));

var port = args.Length > 0 ? args[0] : "5050";
app.Urls.Add($"http://0.0.0.0:{port}");

Console.WriteLine(@"
╔══════════════════════════════════════════╗
║   LucentMist API v0.9.0                  ║
║   智能网络分析助手                       ║
╠══════════════════════════════════════════╣
║   地址: http://0.0.0.0:" + port.PadRight(22) + @"║
║   健康: /api/v1/health                   ║
║   扫描: /api/v1/scan                     ║
║   Agent: /api/v1/agent/chat              ║
╚══════════════════════════════════════════╝
");

app.Run();

/// <summary>
/// 暴露给 WebApplicationFactory 做集成测试
/// </summary>
public partial class Program { }
