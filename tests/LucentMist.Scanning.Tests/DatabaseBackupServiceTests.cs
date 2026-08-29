using Microsoft.Data.Sqlite;

namespace LucentMist.Scanning.Tests;

public sealed class DatabaseBackupServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"lmist-backup-tests-{Guid.NewGuid():N}");

    public DatabaseBackupServiceTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public void Backup_IncludesCommittedWalDataAndPassesIntegrityCheck()
    {
        var database = Path.Combine(_directory, "source.db");
        var backup = Path.Combine(_directory, "backup.db");
        using var writer = Open(database);
        Execute(writer, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;");
        Execute(writer, "CREATE TABLE evidence (value TEXT NOT NULL);");
        Execute(writer, "INSERT INTO evidence (value) VALUES ('wal-row');");
        Assert.True(File.Exists(database + "-wal"));

        var result = DatabaseBackupService.Backup(database, backup);

        Assert.Equal(Path.GetFullPath(backup), result);
        using var restored = Open(backup, SqliteOpenMode.ReadOnly);
        using var read = restored.CreateCommand();
        read.CommandText = "SELECT value FROM evidence";
        Assert.Equal("wal-row", Convert.ToString(read.ExecuteScalar()));
    }

    [Fact]
    public void Restore_ValidatesBackupAndKeepsRecoverableSafetyCopy()
    {
        var source = Path.Combine(_directory, "source.db");
        var backup = Path.Combine(_directory, "backup.db");
        var target = Path.Combine(_directory, "target.db");
        using (var connection = Open(source))
        {
            Execute(connection, "CREATE TABLE evidence (value TEXT NOT NULL);");
            Execute(connection, "INSERT INTO evidence (value) VALUES ('from-backup');");
        }
        DatabaseBackupService.Backup(source, backup);
        using (var connection = Open(target))
        {
            Execute(connection, "CREATE TABLE evidence (value TEXT NOT NULL);");
            Execute(connection, "INSERT INTO evidence (value) VALUES ('old-target');");
        }

        var result = DatabaseBackupService.Restore(backup, target);

        Assert.NotNull(result.SafetyCopyDirectory);
        Assert.True(Directory.Exists(result.SafetyCopyDirectory));
        Assert.True(File.Exists(Path.Combine(result.SafetyCopyDirectory!, "target.db")));
        using var restored = Open(target, SqliteOpenMode.ReadOnly);
        using var read = restored.CreateCommand();
        read.CommandText = "SELECT value FROM evidence";
        Assert.Equal("from-backup", Convert.ToString(read.ExecuteScalar()));
    }

    [Fact]
    public void Backup_RefusesToOverwriteWithoutExplicitFlag()
    {
        var database = Path.Combine(_directory, "source.db");
        var backup = Path.Combine(_directory, "backup.db");
        using (var connection = Open(database))
            Execute(connection, "CREATE TABLE evidence (value TEXT);");
        File.WriteAllText(backup, "existing");

        Assert.Throws<IOException>(() =>
            DatabaseBackupService.Backup(database, backup));
    }

    private static SqliteConnection Open(
        string path,
        SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
