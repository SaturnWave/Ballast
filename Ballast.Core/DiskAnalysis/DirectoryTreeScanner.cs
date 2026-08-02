using System.Diagnostics;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.DiskAnalysis;

/// <summary>Knobs for a tree scan. The defaults keep full fidelity.</summary>
public sealed record TreeScanOptions
{
    /// <summary>
    /// When false, files contribute their bytes to the folder totals but get no node of their own.
    /// Cuts memory dramatically on a whole-drive scan at the cost of
    /// <see cref="LargestItemsFinder.LargestFiles"/> having nothing to report.
    /// </summary>
    public bool IncludeFiles { get; init; } = true;

    /// <summary>
    /// Files smaller than this get no node (their bytes are still counted in every ancestor).
    /// A few MB is enough to shrink a million-file tree to something a UI can hold, while still
    /// keeping every file a "largest files" list would ever show.
    /// </summary>
    public long MinimumFileSizeBytes { get; init; }

    public static TreeScanOptions Default { get; } = new();
}

/// <summary>
/// Outcome of a tree scan: the aggregated tree plus what it cost.
/// </summary>
/// <param name="Root">Root node, with every folder's size already aggregated over its subtree.</param>
/// <param name="SkippedCount">Entries or folders that could not be read (denied, locked, vanished).</param>
/// <param name="FolderCount">Folders visited, including the root.</param>
/// <param name="FileCount">Files measured, including those with no node of their own.</param>
public sealed record TreeScanResult(DirNode Root, int SkippedCount, long FolderCount, long FileCount)
{
    public long TotalBytes => Root.SizeBytes;

    /// <summary>True when part of the tree was unreadable, so the total is a floor, not the truth.</summary>
    public bool IsPartial => SkippedCount > 0;
}

/// <summary>
/// Measures a directory tree. Read-only by construction: this type opens no file handles for
/// writing and deletes nothing — it only asks the filesystem how big things are.
/// </summary>
/// <remarks>
/// <para>
/// The walk is iterative with an explicit stack. A recursive walk overflows on deep trees
/// (node_modules chains, long backup paths), and there is no way to catch that.
/// </para>
/// <para>
/// Reparse points (junctions, symlinks, OneDrive placeholders' targets) are never followed —
/// <c>C:\Users\All Users</c> alone would otherwise loop forever. This means a folder reached
/// only through a junction is not measured, which is the correct answer anyway: its bytes live
/// somewhere else on the volume and are counted there.
/// </para>
/// <para>
/// Hard links and NTFS-deduplicated files are counted once per path, so a tree containing
/// several links to the same data reports more bytes than the volume actually holds.
/// </para>
/// </remarks>
public sealed class DirectoryTreeScanner
{
    /// <summary>Shared instance for callers that are not using dependency injection. Stateless and thread-safe.</summary>
    public static DirectoryTreeScanner Shared { get; } = new();

    /// <summary>Progress is reported no more often than one of these two gates allows.</summary>
    private const int FoldersPerReport = 400;

    private static readonly TimeSpan ReportInterval = TimeSpan.FromMilliseconds(250);

    private static readonly EnumerationOptions _options = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        // Junctions/symlinks (a walk could escape or loop) plus cloud placeholders, which occupy
        // no real local disk and would otherwise inflate every total. See CloudFiles.
        AttributesToSkip = CloudFiles.PlaceholderAttributes,
    };

    /// <summary>
    /// Walks <paramref name="rootPath"/> on a background thread and returns its aggregated tree.
    /// Use <see cref="ScanDetailedAsync"/> when you also need the skipped/visited counts.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is blank or unusable.</exception>
    /// <exception cref="DirectoryNotFoundException"><paramref name="rootPath"/> is not an existing directory.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> fired.</exception>
    public async Task<DirNode> ScanAsync(
        string rootPath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default) =>
        (await ScanDetailedAsync(rootPath, null, progress, ct).ConfigureAwait(false)).Root;

    /// <summary>
    /// Walks <paramref name="rootPath"/> on a background thread and reports what it found and
    /// what it had to skip. Argument validation throws synchronously; everything that goes wrong
    /// during the walk itself is counted, not thrown.
    /// </summary>
    public Task<TreeScanResult> ScanDetailedAsync(
        string rootPath,
        TreeScanOptions? options = null,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var root = ValidateRoot(rootPath);
        var opts = options ?? TreeScanOptions.Default;

        return Task.Run(() => ScanCore(root, opts, progress, ct), ct);
    }

    private static TreeScanResult ScanCore(
        string rootPath,
        TreeScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        var root = new DirNode
        {
            Name = LeafName(rootPath),
            FullPath = rootPath,
            IsDirectory = true,
        };

        // Discovery order: a parent is always appended before any of its children, which is what
        // lets the aggregation pass below run backwards instead of recursing.
        var order = new List<DirNode>(1024) { root };
        var stack = new Stack<DirNode>();
        stack.Push(root);

        int skipped = 0;
        long folders = 0;
        long files = 0;
        long bytes = 0;

        long stamp = Stopwatch.GetTimestamp();
        int foldersSinceReport = 0;

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();

            var dir = stack.Pop();
            folders++;
            foldersSinceReport++;

            if (progress is not null &&
                (foldersSinceReport >= FoldersPerReport || Stopwatch.GetElapsedTime(stamp) >= ReportInterval))
            {
                progress.Report(new ScanProgress(dir.FullPath, folders, bytes));
                foldersSinceReport = 0;
                stamp = Stopwatch.GetTimestamp();
            }

            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(dir.FullPath).EnumerateFileSystemInfos("*", _options);
            }
            catch (Exception ex) when (IsExpected(ex))
            {
                skipped++;
                continue;
            }

            // Enumeration is lazy, so MoveNext itself can fail (drive yanked, path too long).
            // Driving the enumerator by hand is the only way to survive that without losing
            // the folders already on the stack.
            using var enumerator = entries.GetEnumerator();

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                FileSystemInfo? entry = null;
                try
                {
                    if (enumerator.MoveNext()) entry = enumerator.Current;
                }
                catch (Exception ex) when (IsExpected(ex))
                {
                    skipped++;
                    break; // this folder is done; the rest of the tree is not
                }

                if (entry is null) break; // enumeration finished cleanly

                try
                {
                    var attributes = entry.Attributes;

                    // Belt and braces: AttributesToSkip already filters these out.
                    if (CloudFiles.IsPlaceholder(attributes)) continue;

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        var child = new DirNode
                        {
                            Name = entry.Name,
                            FullPath = entry.FullName,
                            IsDirectory = true,
                            Parent = dir,
                        };

                        dir.Children.Add(child);
                        order.Add(child);
                        stack.Push(child);
                        continue;
                    }

                    long length = entry is FileInfo file ? Math.Max(0, file.Length) : 0;

                    dir.SizeBytes += length;
                    dir.FileCount++;
                    files++;
                    bytes += length;

                    if (options.IncludeFiles && length >= options.MinimumFileSizeBytes)
                    {
                        dir.Children.Add(new DirNode
                        {
                            Name = entry.Name,
                            FullPath = entry.FullName,
                            IsDirectory = false,
                            SizeBytes = length,
                            FileCount = 1,
                            Parent = dir,
                        });
                    }
                }
                catch (Exception ex) when (IsExpected(ex))
                {
                    skipped++;
                }
            }
        }

        // Aggregate bottom-up. Children sit after their parent in `order`, so walking backwards
        // guarantees a node is complete before it is folded into its own parent.
        for (int i = order.Count - 1; i >= 1; i--)
        {
            ct.ThrowIfCancellationRequested();

            var node = order[i];
            if (node.Parent is { } parent)
            {
                parent.SizeBytes += node.SizeBytes;
                parent.FileCount += node.FileCount;
            }
        }

        progress?.Report(new ScanProgress(root.FullPath, folders, bytes, 1d));

        return new TreeScanResult(root, skipped, folders, files);
    }

    /// <summary>Failures we expect from a live filesystem and treat as "skip and carry on".</summary>
    private static bool IsExpected(Exception ex) =>
        ex is UnauthorizedAccessException or IOException or System.Security.SecurityException;

    private static string LeafName(string fullPath)
    {
        var trimmed = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var name = Path.GetFileName(trimmed);
        return name.Length > 0 ? name : fullPath; // drive roots have no leaf name
    }

    private static string ValidateRoot(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("A root path is required.", nameof(rootPath));

        string full;
        try
        {
            full = Path.GetFullPath(rootPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArgumentException($"'{rootPath}' is not a usable path.", nameof(rootPath), ex);
        }

        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException($"'{full}' does not exist or is not a directory.");

        return full;
    }
}
