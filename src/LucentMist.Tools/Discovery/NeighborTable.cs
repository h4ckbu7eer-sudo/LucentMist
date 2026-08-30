using System.Diagnostics;
using System.Text.RegularExpressions;

namespace LucentMist.Tools.Discovery;

internal static partial class NeighborTable
{
    internal static async Task<IReadOnlyDictionary<string, string>> ReadAsync(IReadOnlyCollection<string> targets, CancellationToken ct)
    {
        var wanted = targets.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (wanted.Count == 0) return new Dictionary<string, string>();
        var (fileName, arguments) = OperatingSystem.IsWindows() ? ("arp", "-a") : ("ip", "neigh show");
        try
        {
            var startInfo = new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var process = Process.Start(startInfo);
            if (process == null) return new Dictionary<string, string>();
            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            return Parse(output).Where(pair => wanted.Contains(pair.Key)).ToDictionary(StringComparer.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return new Dictionary<string, string>(); }
    }

    internal static IReadOnlyDictionary<string, string> Parse(string output)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in NeighborRegex().Matches(output))
            result[match.Groups["ip"].Value] = match.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant();
        return result;
    }

    [GeneratedRegex(@"(?<ip>(?:\d{1,3}\.){3}\d{1,3}).*?(?<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})")]
    private static partial Regex NeighborRegex();
}
