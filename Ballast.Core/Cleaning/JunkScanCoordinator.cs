using Ballast.Core.Abstractions;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>
/// Runs every junk scanner and merges their results.
///
/// Scanners are independent, so they run concurrently; a scanner that throws is reported as a
/// skipped source rather than failing the whole scan — a broken browser profile should not stop
/// the user from clearing their temp folder.
/// </summary>
public sealed class JunkScanCoordinator
{
    private readonly IReadOnlyList<IScanner> _scanners;

    public JunkScanCoordinator(IEnumerable<IScanner>? scanners = null)
        => _scanners = scanners?.ToArray() ?? Default();

    /// <summary>The scanners enabled by default, in display order.</summary>
    public static IReadOnlyList<IScanner> Default() =>
    [
        new TempFilesScanner(),
        new BrowserCacheScanner(),
        new ThumbnailCacheScanner(),
        new CrashDumpsScanner(),
        new RecycleBinScanner(),
        new WindowsTempScanner(),
        new WindowsUpdateCacheScanner(),
    ];

    public IReadOnlyList<IScanner> Scanners => _scanners;

    public async Task<ScanResult> ScanAllAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        // Each scanner reports figures cumulative *for itself*, so we keep one slot per scanner
        // and sum the slots. Summing the raw reports instead would multiply-count.
        var itemSlots = new long[_scanners.Count];
        var byteSlots = new long[_scanners.Count];
        var gate = new object();

        var tasks = _scanners.Select(async (scanner, index) =>
        {
            IProgress<ScanProgress>? relay = progress is null
                ? null
                : new Progress<ScanProgress>(p =>
                {
                    long items, bytes;
                    lock (gate)
                    {
                        itemSlots[index] = p.ItemsFound;
                        byteSlots[index] = p.BytesFound;
                        items = itemSlots.Sum();
                        bytes = byteSlots.Sum();
                    }
                    progress.Report(new ScanProgress(p.CurrentPath, items, bytes));
                });

            try
            {
                return (scanner, result: await scanner.ScanAsync(relay, ct).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                return (scanner, result: new ScanResult { SkippedPaths = [scanner.Name] });
            }
        });

        var completed = await Task.WhenAll(tasks).ConfigureAwait(false);

        var items = new List<CleanupItem>();
        var skipped = new List<string>();

        foreach (var (_, result) in completed)
        {
            items.AddRange(result.Items);
            skipped.AddRange(result.SkippedPaths);
        }

        // Present the biggest wins first.
        items.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

        progress?.Report(new ScanProgress(
            "Done", items.Count, items.Sum(i => i.SizeBytes), 1.0));

        return new ScanResult { Items = items, SkippedPaths = skipped };
    }

    /// <summary>Groups a scan result into the per-category sections the UI renders.</summary>
    public static IReadOnlyList<(JunkCategory Category, List<CleanupItem> Items, long Bytes)>
        GroupByCategory(ScanResult result)
        => result.Items
            .GroupBy(i => i.Category)
            .Select(g => (g.Key, g.ToList(), g.Sum(i => i.SizeBytes)))
            .OrderByDescending(t => t.Item3)
            .ToList();
}
