using System.Net.Http.Headers;
using LucentMist.Core.Logging;
using LucentMist.Scanning;
using LucentMist.Web;
using LucentMist.Web.Components;
using LucentMist.Web.Hubs;
using Microsoft.AspNetCore.SignalR;

var builder = WebApplication.CreateBuilder(args);
var maintenanceOwner = Environment.GetEnvironmentVariable("LMIST_DB_MAINTENANCE_OWNER") ?? "both";

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSignalR();
builder.Services.AddLogging(b => b.AddSimpleFile(
    Environment.GetEnvironmentVariable("LMIST_LOG_FILE") ?? Path.Combine("logs", "lucentmist-web.log")));

builder.WebHost.ConfigureKestrel(options =>
{
    var maxConnections = int.TryParse(
        Environment.GetEnvironmentVariable("LMIST_MAX_CONNECTIONS"),
        out var parsed) ? parsed : 512;
    options.Limits.MaxConcurrentConnections = Math.Max(16, maxConnections);
    options.Limits.MaxConcurrentUpgradedConnections = Math.Max(8, maxConnections / 4);
});
builder.Services.AddScoped<AppState>();
builder.Services.AddSingleton<ScanService>();
builder.Services.AddTransient<ScanTaskClient>();
builder.Services.AddHttpClient("AgentApi", client =>
{
    client.BaseAddress = new Uri(
        Environment.GetEnvironmentVariable("LMIST_API_URL") ?? "http://localhost:5050");
    client.Timeout = TimeSpan.FromMinutes(5);
    var apiToken = Environment.GetEnvironmentVariable("LMIST_API_TOKEN");
    if (!string.IsNullOrWhiteSpace(apiToken))
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", apiToken);
});

// 扫描后台任务：与 API 共用同一套持久化 + 队列 + worker
builder.Services.AddSingleton(new ScanStore(
    Environment.GetEnvironmentVariable("LMIST_DB") ?? Path.Combine("data", "lucentmist.db")));
builder.Services.AddSingleton<ScanCoordinator>();
builder.Services.AddSingleton<IScanCoordinator>(sp =>
    sp.GetRequiredService<ScanCoordinator>());
builder.Services.AddSingleton<IScanProgressPublisher>(sp =>
    new SignalRScanProgressPublisher(sp.GetRequiredService<IHubContext<ScanHub>>()));
builder.Services.AddHostedService<ScanWorker>();
if (maintenanceOwner is "both" or "web")
    builder.Services.AddHostedService<DatabaseMaintenanceService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}

app.UseMiddleware<BasicAuthMiddleware>();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.MapHub<ScanHub>("/scanhub");

var port = args.Length > 0 ? args[0] : "5051";
var bindAddress = Environment.GetEnvironmentVariable("LMIST_WEB_BIND") ?? "127.0.0.1";
var aspnetUrls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
var remoteViaUrls = !string.IsNullOrWhiteSpace(aspnetUrls) &&
    aspnetUrls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Any(url => !Uri.TryCreate(url, UriKind.Absolute, out var parsed) ||
                    parsed.Host is not ("localhost" or "127.0.0.1" or "::1"));
app.Urls.Add($"http://{bindAddress}:{port}");

if ((bindAddress is not ("127.0.0.1" or "localhost" or "::1") || remoteViaUrls) &&
    (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_WEB_USER")) ||
     string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LMIST_WEB_PASSWORD"))))
{
    Console.Error.WriteLine(
        "拒绝启动：Web 监听非回环地址时必须同时设置 LMIST_WEB_USER 和 LMIST_WEB_PASSWORD。");
    throw new InvalidOperationException(
        "Web 监听非回环地址时必须同时设置 LMIST_WEB_USER 和 LMIST_WEB_PASSWORD");
}

Console.WriteLine($"""
╔══════════════════════════════════════════╗
║   LucentMist Web v{LucentMist.Core.AppVersion.Current}                  ║
║   智能网络分析助手 - Web 管理界面        ║
╠══════════════════════════════════════════╣
║   地址: http://localhost:{port}           ║
║   仪表板: /                              ║
║   设备: /devices                         ║
║   扫描: /scan                            ║
╚══════════════════════════════════════════╝
""");

app.Run();
