using System.ComponentModel.DataAnnotations;
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
        var scanType = request.ScanType ?? "ping";

        string taskId;
        try
        {
            taskId = await _coordinator.StartAsync(
                request.Target,
                scanType,
                request.Ports,
                ct,
                new ScanRequestContext("api", request.PublicTargetAuthorized));
        }
        catch (InvalidScanRequestException ex)
        {
            return BadRequest(new
            {
                error = new
                {
                    code = ex.Code,
                    message = ex.Message,
                },
            });
        }
        catch (ScanQueueFullException ex)
        {
            return StatusCode(503, new
            {
                error = new
                {
                    code = "QUEUE_FULL",
                    message = ex.Message,
                },
            });
        }
        _logger.LogInformation("扫描任务已入队: TaskId={TaskId}, Target={Target}", taskId, request.Target);

        Response.Headers.Location = $"/api/v1/scan/{Uri.EscapeDataString(taskId)}";
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

}

public class ScanRequest
{
    [MaxLength(253)]
    public string Target { get; set; } = "";
    [MaxLength(16)]
    public string ScanType { get; set; } = "ping";
    [MaxLength(64)]
    public string Ports { get; set; } = "";
    public bool PublicTargetAuthorized { get; set; }
}
