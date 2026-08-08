using LucentMist.Web;
using LucentMist.Web.Hubs;
using LucentMist.Web.Components;
using LucentMist.Scanning;
using Microsoft.AspNetCore.SignalR;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSignalR();
builder.Services.AddScoped<AppState>();
builder.Services.AddSingleton<ScanService>();
builder.Services.AddScoped<ScanTaskClient>();

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

app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.MapHub<ScanHub>("/scanhub");

var port = args.Length > 0 ? args[0] : "5051";
app.Urls.Add($"http://0.0.0.0:{port}");

Console.WriteLine($"""
╔══════════════════════════════════════════╗
║   LucentMist Web v0.3.0                  ║
║   智能网络分析助手 - Web 管理界面        ║
╠══════════════════════════════════════════╣
║   地址: http://localhost:{port}           ║
║   仪表板: /                              ║
║   设备: /devices                         ║
║   扫描: /scan                            ║
╚══════════════════════════════════════════╝
""");

app.Run();
