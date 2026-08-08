using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace LucentMist.API.Tests;

/// <summary>
/// ScanController 集成测试 — 用 WebApplicationFactory 起真实 API。
/// 测试用临时 SQLite，避免污染开发库。
/// </summary>
public class ScanApiIntegrationTests : IClassFixture<ScanApiFixture>
{
    private readonly HttpClient _client;

    public ScanApiIntegrationTests(ScanApiFixture fixture)
    {
        _client = fixture.Client;
    }

    [Fact]
    public async Task Health_Returns200()
    {
        var resp = await _client.GetAsync("/api/v1/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task CreateScan_EmptyTarget_Returns400()
    {
        var resp = await _client.PostAsJsonAsync("/api/v1/scan", new { target = "", scanType = "ping" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task CreateScan_ValidTarget_Returns202WithTaskId()
    {
        var resp = await _client.PostAsJsonAsync("/api/v1/scan", new { target = "127.0.0.1", scanType = "ping" });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var body = await resp.Content.ReadFromJsonAsync<CreateResponse>();
        Assert.NotNull(body);
        Assert.False(string.IsNullOrWhiteSpace(body.TaskId));
        Assert.Equal("pending", body.Status);
    }

    [Fact]
    public async Task GetStatus_Nonexistent_Returns404()
    {
        var resp = await _client.GetAsync("/api/v1/scan/nonexistent-task-id");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Scan_ReachesCompletedState()
    {
        // 创建真实扫描任务（127.0.0.1 必在线），轮询直到 completed 或超时
        var create = await _client.PostAsJsonAsync("/api/v1/scan", new { target = "127.0.0.1", scanType = "ping" });
        Assert.Equal(HttpStatusCode.Accepted, create.StatusCode);
        var created = await create.Content.ReadFromJsonAsync<CreateResponse>();
        Assert.NotNull(created);

        var taskId = created.TaskId;
        string? status = null;
        for (int i = 0; i < 30 && status != "completed" && status != "failed"; i++)
        {
            await Task.Delay(500);
            var statusResp = await _client.GetAsync($"/api/v1/scan/{taskId}");
            if (!statusResp.IsSuccessStatusCode) continue;
            var detail = await statusResp.Content.ReadFromJsonAsync<StatusResponse>();
            status = detail?.Status;
        }

        Assert.True(status is "completed" or "failed",
            $"扫描任务未在 15s 内结束，最终状态: {status}");
    }

    [Fact]
    public async Task ListScans_Returns200()
    {
        var resp = await _client.GetAsync("/api/v1/scan?page=1&size=5");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}

public class ScanApiFixture : IDisposable
{
    public HttpClient Client { get; }

    public ScanApiFixture()
    {
        // 用临时库，避免污染开发数据库
        var tempDb = Path.Combine(Path.GetTempPath(), $"lmist-test-{Guid.NewGuid():N}.db");
        Environment.SetEnvironmentVariable("LMIST_DB", tempDb);

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(b => b.UseSetting("environment", "Production"));
        Client = factory.CreateClient();
    }

    public void Dispose()
    {
        Client.Dispose();
    }
}

public class CreateResponse
{
    public string TaskId { get; set; } = "";
    public string Status { get; set; } = "";
}

public class StatusResponse
{
    public string Status { get; set; } = "";
}
