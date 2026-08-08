using Akka.Actor;
using LucentMist.Core.Actors;
using LucentMist.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Extensions;

/// <summary>
/// Core 层 DI 注册扩展
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 注册 Core 层的所有服务
    /// </summary>
    public static IServiceCollection AddLucentMistCore(this IServiceCollection services)
    {
        // 记忆存储
        services.AddSingleton<IMemoryStore, ShortTermMemory>();

        // 会话管理
        services.AddSingleton<ISessionManager, InMemorySessionManager>();

        // Actor 系统
        services.AddSingleton(provider =>
        {
            var system = ActorSystem.Create("LucentMist");
            return system;
        });

        // Actor 工厂
        services.AddSingleton<IActorRefFactory>(provider =>
            provider.GetRequiredService<ActorSystem>());

        // 注册 Core Actor
        services.AddTransient<ScannerActor>();
        services.AddTransient<AnalyzerActor>();
        services.AddTransient<SessionActor>();

        // 默认 IScanner 实现：宿主未注入真实扫描器时明确报错，而不是静默空转
        services.TryAddSingleton<IScanner>(_ =>
            throw new InvalidOperationException(
                "未注册 IScanner 实现。请由宿主注入真实扫描器（如包装 PingScanTool）。"));

        return services;
    }

    /// <summary>
    /// 创建并获取 ScannerActor 的引用
    /// </summary>
    public static IActorRef GetScannerActor(this IActorRefFactory system, IServiceProvider provider)
    {
        var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
        var scanner = provider.GetRequiredService<IScanner>();
        return system.ActorOf(Props.Create(() => new ScannerActor(scanner, loggerFactory)), "scanner");
    }

    /// <summary>
    /// 创建并获取 AnalyzerActor 的引用
    /// </summary>
    public static IActorRef GetAnalyzerActor(this IActorRefFactory system, IServiceProvider provider)
    {
        var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
        return system.ActorOf(Props.Create(() => new AnalyzerActor(loggerFactory)), "analyzer");
    }

    /// <summary>
    /// 创建并获取 SessionActor 的引用
    /// </summary>
    public static IActorRef GetSessionActor(this IActorRefFactory system, IServiceProvider provider)
    {
        var sessionManager = provider.GetRequiredService<ISessionManager>();
        var loggerFactory = provider.GetRequiredService<ILoggerFactory>();
        return system.ActorOf(Props.Create(() => new SessionActor(sessionManager, loggerFactory)), "session");
    }
}
