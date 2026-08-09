using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Sockets;
using LucentMist.Scanning;
using Microsoft.AspNetCore.Mvc;

namespace LucentMist.API.Controllers;

[ApiController]
[Route("api/v1/scan")]
public class ScanController : ControllerBase
{
    private readonly IScanCoordinator _coordinator;
    private readonly ScanStore _store;
    private readonly ILogger<ScanController> _logger;

    public ScanController(IScanCoordinator coordinator, ScanStore store, ILogger<ScanController> logger)
    {
        _coordinator = coordinator;
        _store = store;
        _logger = logger;
    }

    [HttpPost]
    public async Task<IActionResult> CreateScan([FromBody] ScanRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Target))
            return BadRequest(new { error = new { code = "INVALID_TARGET", message = "必须指定扫描目标" } });

        if (!IsValidTarget(request.Target))
            return BadRequest(new
            {
                error = new
                {
                    code = "INVALID_TARGET",
                    message = "目标必须是合法 IP、CIDR、域名或主机名，且不能是全互联网范围",
                },
            });

        var taskId = await _coordinator.StartAsync(request.Target, request.ScanType, request.Ports, ct);
        _logger.LogInformation("扫描任务已入队: TaskId={TaskId}, Target={Target}", taskId, request.Target);

        return Accepted(new { taskId, status = "pending", message = "扫描任务已创建" });
    }

    [HttpGet("{taskId}")]
    public async Task<IActionResult> GetScanStatus(string taskId)
    {
        var task = await _store.GetAsync(taskId);
        if (task == null)
            return NotFound(new { error = new { code = "NOT_FOUND", message = $"任务 {taskId} 不存在" } });

        return Ok(new
        {
            taskId = task.Id,
            target = task.Target,
            scanType = task.ScanType,
            status = task.Status,
            createdAt = task.CreatedAt,
            startedAt = task.StartedAt,
            completedAt = task.CompletedAt,
            totalDevices = task.TotalDevices,
            result = task.ResultJson != null ? ParseResult(task.ResultJson) : null,
            error = task.ErrorMessage,
        });
    }

    [HttpGet]
    public async Task<IActionResult> ListScans([FromQuery] int page = 1, [FromQuery] int size = 20)
    {
        size = Math.Clamp(size, 1, 100);
        page = Math.Max(page, 1);
        var items = await _store.ListAsync(page, size);
        return Ok(new { page, size, items });
    }

    private static object? ParseResult(string json)
    {
        try { return System.Text.Json.JsonSerializer.Deserialize<object>(json); }
        catch { return json; }
    }

    private static bool IsValidTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        if (target.Length > 253) return false;
        if (target.IndexOf('\0') >= 0 || target.IndexOf('\n') >= 0 || target.IndexOf('\r') >= 0) return false;

        if (target.Contains('/'))
        {
            var parts = target.Split('/', 2);
            if (!IPAddress.TryParse(parts[0], out var ip) ||
                ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            if (!int.TryParse(parts[1], out var prefix) || prefix is < 8 or > 30)
                return false;
            return true;
        }

        return IPAddress.TryParse(target, out var address) &&
               address.AddressFamily == AddressFamily.InterNetwork;
    }
}

public class ScanRequest
{
    [MaxLength(253)]
    public string Target { get; set; } = "";
    [MaxLength(16)]
    public string ScanType { get; set; } = "ping";
    [MaxLength(64)]
    public string Ports { get; set; } = "";
}
