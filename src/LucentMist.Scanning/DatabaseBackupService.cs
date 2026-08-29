using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning;

/// <summary>
/// SQLite 在线备份与可回滚恢复。备份不直接复制启用 WAL 的 .db 文件。
/// </summary>
public static class DatabaseBackupService
{
    public static string Backup(string databasePath, string destinationPath, bool overwrite = false)
    {
        var sourcePath = Path.GetFullPath(databasePath);
        var outputPath = Path.GetFullPath(destinationPath);
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("数据库文件不存在", sourcePath);
        if (PathsEqual(sourcePath, outputPath))
            throw new InvalidOperationException("备份目标不能与当前数据库相同");
        if (File.Exists(outputPath) && !overwrite)
            throw new IOException($"备份文件已存在：{outputPath}");

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        var tempPath = outputPath + $".tmp-{Guid.NewGuid():N}";
        try
        {
            using var source = Open(sourcePath, SqliteOpenMode.ReadWrite);
            EnsureCheckpoint(source, "FULL");
            using (var destination = Open(tempPath, SqliteOpenMode.ReadWriteCreate))
            {
                source.BackupDatabase(destination);
                EnsureHealthy(destination);
            }

            File.Move(tempPath, outputPath, overwrite);
            return outputPath;
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    public static DatabaseRestoreResult Restore(
        string backupPath,
        string databasePath)
    {
        var sourcePath = Path.GetFullPath(backupPath);
        var targetPath = Path.GetFullPath(databasePath);
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("备份文件不存在", sourcePath);
        if (PathsEqual(sourcePath, targetPath))
            throw new InvalidOperationException("备份文件不能与恢复目标相同");

        using (var sourceCheck = Open(sourcePath, SqliteOpenMode.ReadOnly))
            EnsureHealthy(sourceCheck);

        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        if (File.Exists(targetPath))
        {
            using var current = Open(targetPath, SqliteOpenMode.ReadWrite);
            EnsureCheckpoint(current, "TRUNCATE");
        }

        var tempPath = targetPath + $".restore-{Guid.NewGuid():N}";
        var safetyDirectory = Path.Combine(
            Path.GetDirectoryName(targetPath)!,
            $"pre-restore-{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}");
        try
        {
            using (var source = Open(sourcePath, SqliteOpenMode.ReadOnly))
            using (var destination = Open(tempPath, SqliteOpenMode.ReadWriteCreate))
            {
                source.BackupDatabase(destination);
                EnsureHealthy(destination);
            }

            var existing = new[] { targetPath, targetPath + "-wal", targetPath + "-shm" }
                .Where(File.Exists)
                .ToArray();
            if (existing.Length > 0)
            {
                Directory.CreateDirectory(safetyDirectory);
                foreach (var file in existing)
                    File.Move(file, Path.Combine(safetyDirectory, Path.GetFileName(file)));
            }

            try
            {
                File.Move(tempPath, targetPath);
            }
            catch
            {
                foreach (var file in existing)
                {
                    var safetyCopy = Path.Combine(safetyDirectory, Path.GetFileName(file));
                    if (File.Exists(safetyCopy) && !File.Exists(file))
                        File.Move(safetyCopy, file);
                }
                throw;
            }

            return new DatabaseRestoreResult(
                targetPath,
                existing.Length > 0 ? safetyDirectory : null);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
            if (Directory.Exists(safetyDirectory)
                && !Directory.EnumerateFileSystemEntries(safetyDirectory).Any())
            {
                Directory.Delete(safetyDirectory);
            }
        }
    }

    private static SqliteConnection Open(string path, SqliteOpenMode mode)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var timeout = connection.CreateCommand();
        timeout.CommandText = "PRAGMA busy_timeout=10000;";
        timeout.ExecuteNonQuery();
        return connection;
    }

    private static void EnsureCheckpoint(SqliteConnection connection, string mode)
    {
        using var checkpoint = connection.CreateCommand();
        checkpoint.CommandText = $"PRAGMA wal_checkpoint({mode});";
        using var result = checkpoint.ExecuteReader();
        if (!result.Read() || result.GetInt32(0) != 0)
        {
            throw new InvalidOperationException(
                "数据库仍被占用，WAL checkpoint 未完成；请停止扫描服务后重试");
        }
    }

    private static void EnsureHealthy(SqliteConnection connection)
    {
        using var check = connection.CreateCommand();
        check.CommandText = "PRAGMA quick_check;";
        var result = Convert.ToString(check.ExecuteScalar()) ?? "";
        if (!result.Equals("ok", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"SQLite 完整性检查失败：{result}");
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

public sealed record DatabaseRestoreResult(
    string DatabasePath,
    string? SafetyCopyDirectory);
