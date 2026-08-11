using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace LucentMist.Core.Logging;

public static class FileLoggerExtensions
{
    public static ILoggingBuilder AddSimpleFile(
        this ILoggingBuilder builder,
        string path,
        int maxBytes = 5 * 1024 * 1024)
    {
        builder.Services.AddSingleton<ILoggerProvider>(
            new SimpleFileLoggerProvider(path, maxBytes));
        return builder;
    }
}

public sealed class SimpleFileLoggerProvider : ILoggerProvider
{
    private readonly object _lock = new();
    private readonly string _path;
    private readonly int _maxBytes;

    public SimpleFileLoggerProvider(string path, int maxBytes)
    {
        _path = path;
        _maxBytes = Math.Max(1024, maxBytes);
    }

    public ILogger CreateLogger(string categoryName) =>
        new SimpleFileLogger(this, categoryName);

    public void Write(string line)
    {
        lock (_lock)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            if (File.Exists(_path) && new FileInfo(_path).Length >= _maxBytes)
            {
                var rotated = $"{_path}.1";
                if (File.Exists(rotated)) File.Delete(rotated);
                File.Move(_path, rotated);
            }

            File.AppendAllText(_path, line + Environment.NewLine);
        }
    }

    public void Dispose() { }
}

public sealed class SimpleFileLogger : ILogger
{
    private readonly SimpleFileLoggerProvider _provider;
    private readonly string _category;

    public SimpleFileLogger(SimpleFileLoggerProvider provider, string category)
    {
        _provider = provider;
        _category = category;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel)) return;

        var line = $"{DateTime.UtcNow:O} [{logLevel}] {_category}: {formatter(state, exception)}";
        if (exception != null) line += Environment.NewLine + exception;
        _provider.Write(line);
    }
}
