using Ballast.Core.Abstractions;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>
/// Explorer's thumbnail and icon caches. Safe to remove — Windows regenerates them on demand,
/// though Explorer usually holds them open, so deletion often needs a restart of Explorer.
/// </summary>
public sealed class ThumbnailCacheScanner : IScanner
{
    public string Name => "Thumbnail cache";

    public Task<ScanResult> ScanAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() =>
        {
            var items = new List<CleanupItem>();
            var skipped = new List<string>();

            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "Windows", "Explorer");

            if (!Directory.Exists(dir))
                return new ScanResult();

            long bytes = 0;

            foreach (var pattern in new[] { "thumbcache_*.db", "iconcache_*.db" })
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, pattern);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    skipped.Add(dir);
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Length <= 0) continue;
                        if (!PathSafety.IsDeletable(file)) continue;

                        items.Add(new CleanupItem
                        {
                            Path = file,
                            Category = JunkCategory.ThumbnailCache,
                            SizeBytes = info.Length,
                            Description = info.Name,
                        });

                        bytes += info.Length;
                        progress?.Report(new ScanProgress(file, items.Count, bytes));
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                    {
                        skipped.Add(file);
                    }
                }
            }

            return new ScanResult { Items = items, SkippedPaths = skipped };
        }, ct);
}
