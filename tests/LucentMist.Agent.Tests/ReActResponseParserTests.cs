using LucentMist.Agent.LLM;

namespace LucentMist.Agent.Tests;

public class ReActResponseParserTests
{
    // ==========================================
    // 正常 JSON 解析
    // ==========================================

    [Fact]
    public void Parse_ValidJson_ReturnsCorrectStep()
    {
        var json = @"{""thought"":""需要扫描端口"",""action"":""port_scan"",""action_input"":""{\""target\"":\""127.0.0.1\"",\""ports\"":\""1-100\""}""}";

        var step = ReActResponseParser.Parse(json);

        Assert.Equal("需要扫描端口", step.Thought);
        Assert.Equal("port_scan", step.Action);
        Assert.Contains("127.0.0.1", step.ActionInput);
        Assert.False(step.IsFinal);
    }

    [Fact]
    public void Parse_FinalAnswer_IsFinal()
    {
        var json = @"{""thought"":""信息足够"",""action"":""final_answer"",""action_input"":""扫描完成，发现3台设备""}";

        var step = ReActResponseParser.Parse(json);

        Assert.True(step.IsFinal);
        Assert.Equal("扫描完成，发现3台设备", step.ActionInput);
    }

    [Fact]
    public void Parse_SimpleJson_NoEscaping()
    {
        var json = @"{""thought"":""分析中"",""action"":""ping_scan"",""action_input"":""{\""target\"":\""192.168.1.1\""}""}";

        var step = ReActResponseParser.Parse(json);

        Assert.Equal("ping_scan", step.Action);
        Assert.NotEmpty(step.ActionInput);
    }

    // ==========================================
    // Markdown 代码块包裹
    // ==========================================

    [Fact]
    public void Parse_MarkdownJsonBlock_StripsWrapper()
    {
        var input = @"```json
{""thought"":""扫描开始"",""action"":""port_scan"",""action_input"":""{\""target\"":\""10.0.0.1\""}""}
```";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
        Assert.Contains("10.0.0.1", step.ActionInput);
    }

    [Fact]
    public void Parse_MarkdownPlainBlock_StripsWrapper()
    {
        var input = @"```
{""thought"":""分析"",""action"":""ping_scan"",""action_input"":""{\""target\"":\""127.0.0.1\""}""}
```";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("ping_scan", step.Action);
    }

    // ==========================================
    // 多行 + 噪音
    // ==========================================

    [Fact]
    public void Parse_MultilineWithNoise_FindsFirstValidJson()
    {
        var input = @"我来扫描一下网络
{""thought"":""第一步"",""action"":""ping_scan"",""action_input"":""{\""target\"":\""192.168.1.0/24\""}""}
其他文本忽略";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("ping_scan", step.Action);
        Assert.Contains("192.168.1.0/24", step.ActionInput);
    }

    [Fact]
    public void Parse_MultipleJsonLines_UsesFirst()
    {
        var input = @"
{""thought"":""正确的一行"",""action"":""port_scan"",""action_input"":""{\""target\"":\""10.0.0.1\""}""}
{""thought"":""被忽略"",""action"":""final_answer"",""action_input"":""不应该出现""}";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
    }

    // ==========================================
    // 正则兜底提取
    // ==========================================

    [Fact]
    public void Parse_BrokenJson_RegexFallback()
    {
        var input = @"分析后发现 thought:""网络正常"" action:""final_answer"" action_input:""没有发现异常端口""";

        var step = ReActResponseParser.Parse(input);

        Assert.True(step.IsFinal);
        Assert.NotEmpty(step.Thought);
        Assert.NotEmpty(step.ActionInput);
    }

    [Fact]
    public void Parse_PartialJson_RegexExtracts()
    {
        var input = @"我准备调用工具了
""thought"": ""扫描端口计划""
""action"": ""port_scan""
""action_input"": ""{\""target\"":\""10.119.88.46\"",\""ports\"":\""1-100\""}""
以上是操作内容";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
    }

    [Fact]
    public void Parse_RegexFallback_WithEscapedJsonActionInput()
    {
        var input = @"我准备调用工具了
""thought"": ""扫描端口计划""
""action"": ""port_scan""
""action_input"": ""{\""target\"":\""10.119.88.46\"",\""ports\"":\""1-100\""}""
以上是操作内容";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
        Assert.Contains("10.119.88.46", step.ActionInput);
        Assert.Contains("\"ports\"", step.ActionInput);
    }

    // ==========================================
    // 完全损坏 / 空
    // ==========================================

    [Fact]
    public void Parse_CompletelyGarbled_ReturnsFinalAnswer()
    {
        var input = "我无法确定下一步该做什么，请提供更多信息。";

        var step = ReActResponseParser.Parse(input);

        Assert.True(step.IsFinal);
        Assert.Equal(input, step.ActionInput);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsFinalAnswer()
    {
        var step = ReActResponseParser.Parse("");

        Assert.True(step.IsFinal);
    }

    [Fact]
    public void Parse_WhitespaceOnly_ReturnsFinalAnswer()
    {
        var step = ReActResponseParser.Parse("   \n  \t  ");

        Assert.True(step.IsFinal);
    }

    // ==========================================
    // 边界情况
    // ==========================================

    [Fact]
    public void Parse_JsonWithExtraWhitespace()
    {
        var input = @"  { ""thought"": ""空格测试"" , ""action"": ""final_answer"" , ""action_input"": ""OK"" }  ";

        var step = ReActResponseParser.Parse(input);

        Assert.True(step.IsFinal);
        Assert.Equal("OK", step.ActionInput);
    }

    [Fact]
    public void Parse_UnicodeCharacters()
    {
        var input = @"{""thought"":""分析网络状态"",""action"":""final_answer"",""action_input"":""发现 中文 设备""}";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("发现 中文 设备", step.ActionInput);
    }

    [Fact]
    public void Parse_ActionInputWithNestedJson()
    {
        var input = @"{""thought"":""需要扫描"",""action"":""port_scan"",""action_input"":""{\""target\"":\""127.0.0.1\"",\""ports\"":\""80,443\""}""}";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
        Assert.Contains("target", step.ActionInput);
        Assert.Contains("ports", step.ActionInput);
    }

    [Fact]
    public void Parse_MissingAction_DefaultsToFinalAnswer()
    {
        var input = @"{""thought"":""没有 action 字段""}";

        var step = ReActResponseParser.Parse(input);

        Assert.True(step.IsFinal);
        Assert.Equal("没有 action 字段", step.Thought);
    }

    [Fact]
    public void Parse_SqliteStyleOutput_StillParses()
    {
        // Some LLMs output explanations before JSON
        var input = @"Based on the scan results, I can provide a summary.
{""thought"":""汇总结果"",""action"":""final_answer"",""action_input"":""发现 2 台设备在线""}";

        var step = ReActResponseParser.Parse(input);

        Assert.True(step.IsFinal);
        Assert.Contains("2 台设备", step.ActionInput);
    }

    // ==========================================
    // action_input 对象格式兼容
    // ==========================================

    [Fact]
    public void Parse_ActionInputAsObject_SerializesToString()
    {
        // LLM outputs action_input as JSON object (not string), matching system prompt example
        var input = @"{""thought"":""识别服务"",""action"":""service_identify"",""action_input"":{""target"":""10.119.88.46"",""port"":135}}";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("service_identify", step.Action);
        Assert.Contains("10.119.88.46", step.ActionInput);
        Assert.Contains("135", step.ActionInput);
        // Should be a valid JSON string that can be deserialized to ToolArguments
    }

    [Fact]
    public void Parse_ActionInputAsObject_WithNestedValues()
    {
        var input = @"{""thought"":""扫描"",""action"":""port_scan"",""action_input"":{""target"":""192.168.1.1"",""ports"":""1-1000""}}";

        var step = ReActResponseParser.Parse(input);

        Assert.Equal("port_scan", step.Action);
        Assert.Contains("\"target\"", step.ActionInput);
        Assert.Contains("192.168.1.1", step.ActionInput);
        Assert.Contains("\"ports\"", step.ActionInput);
    }
}
