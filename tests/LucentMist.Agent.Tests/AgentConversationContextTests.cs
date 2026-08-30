using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public class AgentConversationContextTests
{
    [Fact]
    public void FollowUpRetainsPrimaryIpAndGatewayAsData()
    {
        var context = AgentConversationContext.Build([
            new ChatMessage("user", "看看我的ip"),
            new ChatMessage("assistant", "主 IP 192.168.99.9，网关 192.168.99.1"),
        ], "分析那个子网的网关");
        Assert.Contains("192.168.99.9", context);
        Assert.Contains("192.168.99.1", context);
        Assert.Contains("当前用户问题：\n分析那个子网的网关", context);
        Assert.Contains("上下文数据", context);
    }

    [Fact]
    public void HistoryIsBoundedAndNeverReplacesCurrentQuestion()
    {
        var history = Enumerable.Range(0, 100).Select(index => new ChatMessage("user", new string('x', 3000)));
        var context = AgentConversationContext.Build(history, "current question");
        Assert.True(context.Length < 50_000);
        Assert.EndsWith("current question", context);
        Assert.Equal("current question", AgentConversationContext.Build([], "current question"));
    }
}
