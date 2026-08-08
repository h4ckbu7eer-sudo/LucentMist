using System.Diagnostics;
using System.Text.Json;
using LucentMist.Core.Models;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Scanning;

/// <summary>
/// 设备查询工具 — 查询已知设备信息
/// </summary>
public class DeviceQueryTool : ITool
{
    private readonly ILogger<DeviceQueryTool> _logger;
    private readonly List<Device> _deviceStore;

    public string Name => "device_query";
    public string Description => "查询已知设备信息，支持按 IP、MAC、设备类型筛选";

    public ToolParameter[] Parameters => [
        new() { Name = "ip", Type = "string", Description = "按 IP 查询", Required = false },
        new() { Name = "type", Type = "string", Description = "按设备类型查询（router/laptop/phone/iot）", Required = false },
        new() { Name = "active_only", Type = "bool", Description = "仅查询在线设备", Required = false, Default = "true" }
    ];

    public DeviceQueryTool(ILogger<DeviceQueryTool> logger, List<Device> deviceStore)
    {
        _logger = logger;
        _deviceStore = deviceStore;
    }

    public Task<ToolResult> ExecuteAsync(ToolArguments args)
    {
        var sw = Stopwatch.StartNew();
        var ip = args.GetOrDefault("ip");
        var type = args.GetOrDefault("type");
        var activeOnly = args.GetOrDefault("active_only", "true").ToLower() == "true";

        var query = _deviceStore.AsEnumerable();

        if (activeOnly) query = query.Where(d => d.IsActive);
        if (!string.IsNullOrWhiteSpace(ip)) query = query.Where(d => d.IpAddress == ip);
        if (!string.IsNullOrWhiteSpace(type)) query = query.Where(d => d.DeviceType == type);

        var devices = query.ToList();

        var result = new
        {
            total = devices.Count,
            devices = devices.Select(d => new
            {
                d.IpAddress,
                d.MacAddress,
                d.Hostname,
                d.Vendor,
                d.DeviceType,
                d.FirstSeen,
                d.LastSeen
            })
        };

        _logger.LogInformation("DeviceQuery: Found {Count} devices", devices.Count);
        return Task.FromResult(ToolResult.Ok(JsonSerializer.Serialize(result), sw.Elapsed));
    }
}
