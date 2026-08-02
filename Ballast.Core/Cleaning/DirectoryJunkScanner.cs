using Ballast.Core.Abstractions;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>Scans a fixed set of directories and reports their contents as junk.</summary>
public abstract class DirectoryJunkScanner : IScanner
{
    public abstract string Name { get; }

    protected abstract JunkCategory Category { get; }

    protected abstract IEnumerable<string> Roots { get; }

    protected virtual bool RequiresAdmin => false;

    /// <summary>
    /// Items modified more recently than this are skipped: a running installer or a live
    /// browser session may still need them.
    /// </summary>
    protected virtual TimeSpan MinimumAge => TimeSpan.FromHours(24);

    public Task<ScanResult> ScanAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() =>
        {
            var all = new List<CleanupItem>();
            var skipped = new List<string>();

            foreach (var root in Roots)
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(root)) continue;

                var (items, skips) = FileSystemProbe.TopLevelItems(
                    root, Category, RequiresAdmin, MinimumAge, progress, ct);

                all.AddRange(items);
                skipped.AddRange(skips);
            }

            return new ScanResult { Items = all, SkippedPaths = skipped };
        }, ct);
}
