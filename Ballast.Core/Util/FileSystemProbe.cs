using Ballast.Core.Models;

namespace Ballast.Core.Util;

/// <summary>Error-tolerant filesystem walking. Access-denied paths are recorded, never thrown.</summary>
public static class FileSystemProbe
{
    // Skips junctions/symlinks AND cloud placeholders — see CloudFiles for why the latter matters.
    private static readonly EnumerationOptions _options = CloudFiles.ShallowEnumeration();

    /// <summary>Recursively sums the size of a directory. Unreadable subtrees contribute 0.</summary>
    public static long DirectorySize(string dir, List<string>? skipped, CancellationToken ct)
    {
        long total = 0;
        var stack = new Stack<string>();
        stack.Push(dir);

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = stack.Pop();

            try
            {
                foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos("*", _options))
                {
                    if (CloudFiles.IsPlaceholder(entry)) continue;

                    if (entry is FileInfo f)
                    {
                        try { total += f.Length; } catch { /* vanished mid-scan */ }
                    }
                    else
                    {
                        stack.Push(entry.FullName);
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                skipped?.Add(current);
            }
        }

        return total;
    }

    /// <summary>
    /// Enumerates the immediate children of <paramref name="root"/> as cleanup candidates,
    /// aggregating directory sizes. We work at this granularity so the UI list stays readable
    /// and each row deletes in a single recursive operation.
    /// </summary>
    public static (List<CleanupItem> Items, List<string> Skipped) TopLevelItems(
        string root,
        JunkCategory category,
        bool requiresAdmin,
        TimeSpan minimumAge,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        var items = new List<CleanupItem>();
        var skipped = new List<string>();

        if (!Directory.Exists(root)) return (items, skipped);

        DateTime cutoff = DateTime.UtcNow - minimumAge;
        long bytes = 0;

        IEnumerable<FileSystemInfo> children;
        try
        {
            children = new DirectoryInfo(root).EnumerateFileSystemInfos("*", _options);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            skipped.Add(root);
            return (items, skipped);
        }

        foreach (var child in children)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                if (CloudFiles.IsPlaceholder(child)) continue;

                // Leave anything still in active use alone.
                if (minimumAge > TimeSpan.Zero && child.LastWriteTimeUtc > cutoff) continue;

                if (!PathSafety.IsDeletable(child.FullName)) continue;

                bool isDir = child is DirectoryInfo;
                long size = isDir
                    ? DirectorySize(child.FullName, skipped, ct)
                    : ((FileInfo)child).Length;

                if (size <= 0 && !isDir) continue;

                items.Add(new CleanupItem
                {
                    Path = child.FullName,
                    Category = category,
                    SizeBytes = size,
                    IsDirectory = isDir,
                    RequiresAdmin = requiresAdmin,
                });

                bytes += size;
                progress?.Report(new ScanProgress(child.FullName, items.Count, bytes));
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                skipped.Add(child.FullName);
            }
        }

        return (items, skipped);
    }
}
