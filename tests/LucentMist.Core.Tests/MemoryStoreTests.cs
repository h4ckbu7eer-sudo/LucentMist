using LucentMist.Core.Interfaces;

namespace LucentMist.Core.Tests;

public class MemoryStoreTests
{
    private readonly ShortTermMemory _memory = new();

    [Fact]
    public async Task StoreAndRetrieve_ShouldWork()
    {
        await _memory.StoreAsync("test-key", "hello");

        var result = await _memory.RetrieveAsync<string>("test-key");

        Assert.Equal("hello", result);
    }

    [Fact]
    public async Task Retrieve_NonExistent_ReturnsNull()
    {
        var result = await _memory.RetrieveAsync<string>("nonexistent");

        Assert.Null(result);
    }

    [Fact]
    public async Task Store_WithTtl_Expires()
    {
        await _memory.StoreAsync("ttl-key", "temp", TimeSpan.FromMilliseconds(1));
        await Task.Delay(10);

        var result = await _memory.RetrieveAsync<string>("ttl-key");

        Assert.Null(result);
    }

    [Fact]
    public async Task Delete_RemovesValue()
    {
        await _memory.StoreAsync("del-key", "value");
        await _memory.DeleteAsync("del-key");

        var result = await _memory.RetrieveAsync<string>("del-key");

        Assert.Null(result);
    }

    [Fact]
    public async Task Clear_RemovesAll()
    {
        await _memory.StoreAsync("key1", "val1");
        await _memory.StoreAsync("key2", "val2");
        await _memory.ClearAsync();

        var r1 = await _memory.RetrieveAsync<string>("key1");
        var r2 = await _memory.RetrieveAsync<string>("key2");

        Assert.Null(r1);
        Assert.Null(r2);
    }

    [Fact]
    public async Task Query_ByPattern_ReturnsMatches()
    {
        await _memory.StoreAsync("device:192.168.1.1", "router");
        await _memory.StoreAsync("device:192.168.1.2", "laptop");
        await _memory.StoreAsync("alert:critical", "offline");

        var devices = (await _memory.QueryAsync<string>("device:")).ToList();

        Assert.Equal(2, devices.Count);
        Assert.Contains("router", devices);
        Assert.Contains("laptop", devices);
    }
}
