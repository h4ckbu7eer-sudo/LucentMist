using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LucentMist.Scanning;

public sealed class DatabaseMaintenanceService : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<DatabaseMaintenanceService> _logger;
    private readonly int _retentionDays;
    private readonly int _intervalHours;
    private readonly bool _vacuum;

    public DatabaseMaintenanceService(
        IServiceProvider services,
        ILogger<DatabaseMaintenanceService> logger)
    {
        _services = services;
        _logger = logger;
        _retentionDays = Math.Clamp(ParseEnv("LMIST_RETENTION_DAYS", 90), 1, 3650);
        _intervalHours = Math.Clamp(ParseEnv("LMIST_CLEANUP_HOURS", 24), 1, 24 * 30);
        _vacuum = string.Equals(
            Environment.GetEnvironmentVariable("LMIST_DB_VACUUM"),
            "1",
            StringComparison.OrdinalIgnoreCase);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database maintenance failed");
            }

            await Task.Delay(TimeSpan.FromHours(_intervalHours), stoppingToken);
        }
    }

    private async Task CleanupAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var scanStore = scope.ServiceProvider.GetService<ScanStore>();
        var sessionStore = scope.ServiceProvider.GetService<AgentSessionStore>();

        ct.ThrowIfCancellationRequested();
        var scanDeleted = scanStore is null
            ? 0
            : await scanStore.CleanupAsync(_retentionDays, _vacuum);
        var sessionDeleted = sessionStore is null
            ? 0
            : await sessionStore.CleanupAsync(_retentionDays, _vacuum);

        _logger.LogInformation(
            "Database maintenance completed: scans={ScanDeleted}, sessions={SessionDeleted}, retention={RetentionDays}d",
            scanDeleted,
            sessionDeleted,
            _retentionDays);
    }

    private static int ParseEnv(string key, int fallback) =>
        int.TryParse(Environment.GetEnvironmentVariable(key), out var value)
            ? value
            : fallback;
}
