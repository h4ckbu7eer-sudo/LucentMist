using LucentMist.Core.Interfaces;

namespace LucentMist.Core.Tests;

public class SessionManagerTests
{
    private readonly InMemorySessionManager _manager = new();

    [Fact]
    public async Task CreateSession_ShouldAssignId()
    {
        var session = await _manager.CreateAsync("测试会话");

        Assert.NotNull(session.Id);
        Assert.Equal("测试会话", session.Title);
    }

    [Fact]
    public async Task CreateSession_EmptyTitle_UsesDefault()
    {
        var session = await _manager.CreateAsync();

        Assert.Equal("新会话", session.Title);
    }

    [Fact]
    public async Task GetSession_Existing_ReturnsSession()
    {
        var created = await _manager.CreateAsync("会话A");

        var retrieved = await _manager.GetAsync(created.Id);

        Assert.NotNull(retrieved);
        Assert.Equal("会话A", retrieved!.Title);
    }

    [Fact]
    public async Task GetSession_NonExistent_ReturnsNull()
    {
        var session = await _manager.GetAsync("nonexistent-id");

        Assert.Null(session);
    }

    [Fact]
    public async Task DeleteSession_RemovesSession()
    {
        var created = await _manager.CreateAsync("待删除");
        await _manager.DeleteAsync(created.Id);

        var retrieved = await _manager.GetAsync(created.Id);

        Assert.Null(retrieved);
    }

    [Fact]
    public async Task UpdateSession_ChangesTimestamp()
    {
        var session = await _manager.CreateAsync("更新测试");
        var oldTime = session.UpdatedAt;

        await Task.Delay(10);
        session.Title = "已更新";
        await _manager.UpdateAsync(session);

        var updated = await _manager.GetAsync(session.Id);
        Assert.NotNull(updated);
        Assert.True(updated!.UpdatedAt > oldTime);
    }
}
