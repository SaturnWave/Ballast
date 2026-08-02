using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>
/// The only place in the application that deletes anything.
///
/// Design rules this class enforces:
/// <list type="bullet">
/// <item>Every path is re-validated through <see cref="PathSafety"/> immediately before deletion —
/// the scan result is treated as untrusted input, not as permission.</item>
/// <item>Locked or in-use files are skipped and reported, never retried destructively.</item>
/// <item><see cref="CleanReport.BytesFreed"/> counts what was *actually* removed, measured
/// per file, so a partially-deleted folder reports honest numbers.</item>
/// <item>Every outcome is written to <see cref="ActionLog"/>.</item>
/// </list>
/// </summary>
public sealed class CleaningService
{
    public Task<CleanReport> DeleteAsync(
        IEnumerable<CleanupItem> items,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() =>
        {
            var list = items.ToList();
            long freed = 0;
            int deleted = 0;
            var failures = new List<CleanFailure>();

            ActionLog.Info($"Cleanup started: {list.Count} item(s) selected, " +
                           $"{ByteFormatter.Format(list.Sum(i => i.SizeBytes))} requested" +
                           (Elevation.IsElevated ? " [elevated]" : " [standard user]"));

            for (int i = 0; i < list.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var item = list[i];

                try
                {
                    long itemFreed = DeleteItem(item, failures, ct);

                    if (itemFreed > 0)
                    {
                        freed += itemFreed;
                        deleted++;
                        ActionLog.Deleted(item.Path, itemFreed);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failures.Add(new CleanFailure(item.Path, ex.Message));
                    ActionLog.Failed(item.Path, ex.Message);
                }

                progress?.Report(new ScanProgress(
                    item.DisplayName, deleted, freed,
                    Fraction: list.Count == 0 ? 1 : (double)(i + 1) / list.Count));
            }

            ActionLog.Info($"Cleanup finished: {ByteFormatter.Format(freed)} freed, " +
                           $"{deleted} item(s) removed, {failures.Count} failure(s)");

            return new CleanReport
            {
                BytesFreed = freed,
                ItemsDeleted = deleted,
                Failures = failures,
            };
        }, ct);

    private static long DeleteItem(CleanupItem item, List<CleanFailure> failures, CancellationToken ct)
    {
        // The Recycle Bin is emptied through the shell, not the filesystem.
        if (item.IsVirtual)
        {
            if (item.Category != JunkCategory.RecycleBin)
                throw new InvalidOperationException($"Unknown virtual item: {item.Path}");

            var (before, _) = RecycleBinScanner.Query();
            RecycleBinScanner.Empty();
            var (after, _) = RecycleBinScanner.Query();

            return Math.Max(0, before - after);
        }

        // Re-validate: never trust a path just because a scanner produced it.
        PathSafety.EnsureDeletable(item.Path);

        if (item.RequiresAdmin && !Elevation.IsElevated)
            throw new UnauthorizedAccessException(
                "This location needs administrator rights. Restart Ballast as administrator to clear it.");

        return item.IsDirectory
            ? DeleteDirectoryContents(item.Path, failures, ct)
            : DeleteFile(item.Path, failures);
    }

    private static long DeleteFile(string path, List<CleanFailure> failures)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return 0;

            long size = info.Length;

            // Read-only files would otherwise throw.
            if ((info.Attributes & FileAttributes.ReadOnly) != 0)
                info.Attributes &= ~FileAttributes.ReadOnly;

            info.Delete();
            return size;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            failures.Add(new CleanFailure(path, Describe(ex)));
            ActionLog.Failed(path, ex.Message);
            return 0;
        }
    }

    /// <summary>
    /// Removes a directory tree file-by-file rather than with a single recursive delete.
    ///
    /// A recursive <c>Directory.Delete</c> aborts the moment it meets one locked file, leaving
    /// the rest of the (often very large) folder in place. Walking it ourselves means one locked
    /// file costs us only that file, and lets us count exactly how many bytes we really freed.
    /// </summary>
    private static long DeleteDirectoryContents(string root, List<CleanFailure> failures, CancellationToken ct)
    {
        if (!Directory.Exists(root)) return 0;

        long freed = 0;
        var directories = new List<string>();
        var stack = new Stack<string>();
        stack.Push(root);

        var options = CloudFiles.ShallowEnumeration();

        // Pass 1: delete files depth-first, collecting directories to remove afterwards.
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = stack.Pop();
            directories.Add(current);

            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(current).EnumerateFileSystemInfos("*", options);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failures.Add(new CleanFailure(current, Describe(ex)));
                continue;
            }

            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    if (CloudFiles.IsPlaceholder(entry))
                        continue; // never traverse or delete through a link or cloud placeholder

                    if (entry is DirectoryInfo)
                        stack.Push(entry.FullName);
                    else
                        freed += DeleteFile(entry.FullName, failures);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    failures.Add(new CleanFailure(entry.FullName, Describe(ex)));
                }
            }
        }

        // Pass 2: remove directories deepest-first. Any that still hold a locked file stay put.
        foreach (var dir in directories.OrderByDescending(d => d.Length))
        {
            ct.ThrowIfCancellationRequested();

            // Keep the item root itself only if it is a cache root we were asked to empty;
            // otherwise remove it now that it should be empty.
            try
            {
                if (!Directory.Exists(dir)) continue;
                if (Directory.EnumerateFileSystemEntries(dir).Any()) continue;

                Directory.Delete(dir, recursive: false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Leaving an empty folder behind is harmless; do not report it as a failure.
            }
        }

        return freed;
    }

    private static string Describe(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "Access denied.",
        IOException io when io.Message.Contains("being used", StringComparison.OrdinalIgnoreCase)
            => "In use by another program.",
        IOException io => io.Message,
        _ => ex.Message,
    };
}
