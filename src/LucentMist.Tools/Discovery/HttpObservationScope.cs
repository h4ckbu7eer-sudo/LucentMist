using System.Collections.Concurrent;
using LucentMist.Tools.Security;

namespace LucentMist.Tools.Discovery;

/// <summary>Request-scoped public HTTP evidence, never stale process-wide cache.</summary>
public static class HttpObservationScope
{
    private static readonly AsyncLocal<Scope?> Current = new();
    public static IDisposable Begin()
    {
        var scope = new Scope(Current.Value);
        Current.Value = scope;
        return scope;
    }
    private sealed class Scope(Scope? previous) : IDisposable
    {
        internal readonly ConcurrentDictionary<string, Lazy<Task<HttpBannerProbe.Result>>> Results = new();
        public void Dispose() { Current.Value = previous; Results.Clear(); }
    }
    internal static Task<HttpBannerProbe.Result> GetAsync(string target, int port,
        Func<Task<HttpBannerProbe.Result>> probe, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return (Current.Value?.Results.GetOrAdd($"{target}:{port}",
            _ => new Lazy<Task<HttpBannerProbe.Result>>(probe, LazyThreadSafetyMode.ExecutionAndPublication)).Value ?? probe()).WaitAsync(ct);
    }
}
