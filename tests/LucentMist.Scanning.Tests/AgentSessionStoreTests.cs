using LucentMist.Scanning;

namespace LucentMist.Scanning.Tests;

public class AgentSessionStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(
        Path.GetTempPath(), $"lmist-agent-{Guid.NewGuid():N}.db");
    private readonly AgentSessionStore _store;

    public AgentSessionStoreTests()
    {
        _store = new AgentSessionStore(_dbPath);
    }

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [Fact]
    public async Task Create_Then_List_ReturnsSession()
    {
        var session = await _store.CreateSessionAsync("测试会话", "qwen2.5:7b");

        var sessions = await _store.ListSessionsAsync(1, 20);

        Assert.Single(sessions);
        Assert.Equal(session.Id, sessions[0].Id);
        Assert.Equal("测试会话", sessions[0].Title);
    }

    [Fact]
    public async Task AddMessages_Then_GetMessages_ReturnsHistory()
    {
        var session = await _store.CreateSessionAsync("对话", "qwen2.5:7b");

        await _store.AddMessageAsync(session.Id, "user", "扫描网络");
        await _store.AddMessageAsync(session.Id, "assistant", "已扫描");

        var messages = await _store.GetMessagesAsync(session.Id);

        Assert.Equal(2, messages.Count);
        Assert.Equal("user", messages[0].Role);
        Assert.Equal("assistant", messages[1].Role);
    }

    [Fact]
    public async Task Touch_UpdatesMessageCount()
    {
        var session = await _store.CreateSessionAsync("计数", "qwen2.5:7b");

        await _store.AddMessageAsync(session.Id, "user", "a");
        await _store.AddMessageAsync(session.Id, "assistant", "b");

        var loaded = await _store.GetSessionAsync(session.Id);

        Assert.NotNull(loaded);
        Assert.Equal(2, loaded!.MessageCount);
    }
}
