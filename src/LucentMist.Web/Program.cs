using LucentMist.Web;
using LucentMist.Web.Hubs;
using LucentMist.Web.Components;
using LucentMist.Scanning;
using Microsoft.AspNetCore.SignalR;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSignalR();
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

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseMiddleware<BasicAuthMiddleware>();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.MapHub<ScanHub>("/scanhub");

var port = args.Length > 0 ? args[0] : "5051";
var bindAddress = Environment.GetEnvironmentVariable("LMIST_WEB_BIND") ?? "localhost";
app.Urls.Add($"http://{bindAddress}:{port}");

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
