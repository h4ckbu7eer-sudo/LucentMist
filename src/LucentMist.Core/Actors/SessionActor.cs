using LucentMist.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Actors;

/// <summary>
/// 会话 Actor 消息
/// </summary>
public record CreateSession(string Title = "");
public record GetSession(string SessionId);
public record AddMessage(string SessionId, Message Msg);
public record DeleteSession(string SessionId);

/// <summary>
/// 会话管理 Actor — 封装 ISessionManager，提供 Actor 化的会话操作
/// </summary>
public class SessionActor : BaseActor
{
    private readonly ISessionManager _sessionManager;

    public SessionActor(ISessionManager sessionManager, ILoggerFactory loggerFactory)
        : base(loggerFactory)
    {
        _sessionManager = sessionManager;

        Receive<CreateSession>(msg =>
        {
            var sender = Sender;
            var self = Self;
            HandleCreate(msg).ContinueWith(t =>
            {
                if (t.IsFaulted) sender.Tell(new ActorError(t.Exception?.InnerException?.Message ?? "未知错误"), self);
                else sender.Tell(t.Result, self);
            });
        });

        Receive<GetSession>(msg =>
        {
            var sender = Sender;
            var self = Self;
            HandleGet(msg).ContinueWith(t =>
            {
                if (t.IsFaulted) sender.Tell(new ActorError(t.Exception?.InnerException?.Message ?? "未知错误"), self);
                else sender.Tell(t.Result, self);
            });
        });

        Receive<AddMessage>(msg =>
        {
            var sender = Sender;
            var self = Self;
            HandleAddMessage(msg).ContinueWith(t =>
            {
                if (t.IsFaulted) sender.Tell(new ActorError(t.Exception?.InnerException?.Message ?? "未知错误"), self);
                else sender.Tell(t.Result, self);
            });
        });

        Receive<DeleteSession>(msg =>
        {
            var sender = Sender;
            var self = Self;
            HandleDelete(msg).ContinueWith(t =>
            {
                if (t.IsFaulted) sender.Tell(new ActorError(t.Exception?.InnerException?.Message ?? "未知错误"), self);
                else sender.Tell(t.Result, self);
            });
        });
    }

    private async Task<Session> HandleCreate(CreateSession msg)
    {
        var session = await _sessionManager.CreateAsync(msg.Title);
        Logger.LogInformation("会话创建: {SessionId}", session.Id);
        return session;
    }

    private async Task<Session?> HandleGet(GetSession msg)
    {
        var session = await _sessionManager.GetAsync(msg.SessionId);
        if (session == null)
        {
            Logger.LogWarning("会话不存在: {SessionId}", msg.SessionId);
        }
        return session;
    }

    private async Task<Session?> HandleAddMessage(AddMessage msg)
    {
        var session = await _sessionManager.GetAsync(msg.SessionId);
        if (session == null) return null;

        session.Messages.Add(msg.Msg);
        session.MessageCount = session.Messages.Count;
        session.UpdatedAt = DateTime.UtcNow;
        await _sessionManager.UpdateAsync(session);
        return session;
    }

    private async Task<bool> HandleDelete(DeleteSession msg)
    {
        await _sessionManager.DeleteAsync(msg.SessionId);
        Logger.LogInformation("会话删除: {SessionId}", msg.SessionId);
        return true;
    }
}
