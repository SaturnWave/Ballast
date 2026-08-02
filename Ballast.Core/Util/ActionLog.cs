namespace Ballast.Core.Util;

/// <summary>
/// Append-only audit trail of every destructive action, so a user can always find out what the
/// app removed. Deliberately dependency-free (no logging framework) and never throws: a logging
/// failure must not abort a cleanup, and must not crash the app.
/// </summary>
public static class ActionLog
{
    private static readonly object _gate = new();

    public static string LogDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ballast", "logs");

    public static string CurrentLogFile =>
        Path.Combine(LogDirectory, $"Ballast-{DateTime.Now:yyyyMMdd}.log");

    public static void Write(string message)
    {
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(LogDirectory);
                File.AppendAllText(
                    CurrentLogFile,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Logging is best-effort by design.
        }
    }

    public static void Deleted(string path, long bytes) =>
        Write($"DELETED  {ByteFormatter.Format(bytes),10}  {path}");

    public static void Failed(string path, string reason) =>
        Write($"FAILED               {path}  -- {reason}");

    public static void Info(string message) => Write($"INFO     {message}");
}
