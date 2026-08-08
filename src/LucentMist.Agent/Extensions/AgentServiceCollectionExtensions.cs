using LucentMist.Agent.LLM;
using LucentMist.Core.Models;
using LucentMist.Tools;
using LucentMist.Tools.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace LucentMist.Agent.Extensions;

/// <summary>
/// Agent 层 DI 注册扩展
/// </summary>
public static class AgentServiceCollectionExtensions
{
    /// <summary>
    /// 注册 Agent 层所有服务
    /// </summary>
    public static IServiceCollection AddLucentMistAgent(
        this IServiceCollection services,
        string provider = "ollama",
        string model = "qwen2.5:7b",
        string endpoint = "http://localhost:11434",
        string? apiKey = null)
    {
        // LLM Provider
        services.AddSingleton<ILLMProvider>(sp =>
        {
            var logger = sp.GetRequiredService<ILoggerFactory>();
            return provider.ToLower() switch
            {
                "ollama" => new OllamaProvider(endpoint, model,
                    logger.CreateLogger<OllamaProvider>()),
                "claude" => new ClaudeProvider(apiKey ?? "", model,
                    logger.CreateLogger<ClaudeProvider>()),
                _ => throw new ArgumentException($"不支持的 LLM Provider: {provider}")
            };
        });

        // Tool Registry + 注册默认工具
        services.AddSingleton<ToolRegistry>();
        services.AddSingleton(sp =>
        {
            var registry = new ToolRegistry();
            var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
            var deviceStore = new List<Device>();

            registry.Register(new PingScanTool(loggerFactory.CreateLogger<PingScanTool>()));
            registry.Register(new PortScanTool(loggerFactory.CreateLogger<PortScanTool>()));
            registry.Register(new ServiceIdentifyTool(loggerFactory.CreateLogger<ServiceIdentifyTool>()));
            registry.Register(new DeviceQueryTool(loggerFactory.CreateLogger<DeviceQueryTool>(), deviceStore));

            return registry;
        });

        // Agent Service
        services.AddSingleton<AgentService>();

        return services;
    }
}
