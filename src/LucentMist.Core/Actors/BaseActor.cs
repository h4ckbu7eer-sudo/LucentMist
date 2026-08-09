using Akka.Actor;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Actors;

/// <summary>
/// Actor 基类，提供通用日志和生命周期管理
/// </summary>
public abstract class BaseActor : ReceiveActor
{
    protected ILogger Logger { get; }

    protected BaseActor(ILoggerFactory loggerFactory)
    {
        Logger = loggerFactory.CreateLogger(GetType().Name);
    }

    protected override void PreStart()
    {
        Logger.LogDebug("{ActorName} 启动", GetType().Name);
        base.PreStart();
    }

    protected override void PostStop()
    {
        Logger.LogDebug("{ActorName} 停止", GetType().Name);
        base.PostStop();
    }

    /// <summary>
    /// 安全地执行异步操作 — 捕获 Sender 后异步处理
    /// </summary>
    protected void ReceiveAsync<T>(Func<T, Task> handler) where T : class
    {
        Receive<T>(msg =>
        {
            var sender = Sender;
            var self = Self;

            handler(msg).ContinueWith(task =>
            {
                if (task.Exception != null)
                {
                    Logger.LogError(task.Exception, "{ActorName} 处理消息失败: {MessageType}",
                        GetType().Name, typeof(T).Name);
                    sender.Tell(new ActorError(task.Exception.InnerException?.Message ?? task.Exception.Message), self);
                }

            }, TaskContinuationOptions.OnlyOnFaulted);
        });
    }
}

/// <summary>
/// Actor 通用错误消息
/// </summary>
public record ActorError(string Message, string? Detail = null);
