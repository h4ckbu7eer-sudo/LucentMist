using LucentMist.Tools.Scanning;
using Microsoft.Extensions.Logging;

namespace LucentMist.Tools.Tests;

public sealed class ServiceIdentifyLoggingTests
{
    [Fact]
    public void ProcessPathAccessFailure_IsDebugInsteadOfUserVisibleWarning()
    {
        var logger = new CapturingLogger();
        var tool = new ServiceIdentifyTool(logger);

        tool.LogProcessPathUnavailable(
            new UnauthorizedAccessException("expected permission boundary"),
            "protected-process");

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Contains("Process enrichment unavailable", entry.Message);
        Assert.DoesNotContain(logger.Entries, item => item.Level >= LogLevel.Warning);
    }

    private sealed class CapturingLogger : ILogger<ServiceIdentifyTool>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
