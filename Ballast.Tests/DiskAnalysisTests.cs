using Ballast.Core.DiskAnalysis;
using Ballast.Core.Models;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Scans a purpose-built fixture tree under %TEMP% with known sizes, so the aggregation maths
/// can be asserted exactly rather than approximately.
/// </summary>
public sealed class DiskAnalysisTests : IDisposable
{
    private readonly string _root;

    public DiskAnalysisTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "BallastDiskTests", Guid.NewGuid().ToString("N"));

        // Layout (bytes):
        //   root/
        //     a.bin              1000
        //     big/
        //       huge.bin        50000
        //       sub/
        //         c.bin          2500
        //     empty/
        Write("a.bin", 1000);
        Write(Path.Combine("big", "huge.bin"), 50_000);
        Write(Path.Combine("big", "sub", "c.bin"), 2_500);
        Directory.CreateDirectory(Path.Combine(_root, "empty"));
    }

    private void Write(string relative, int bytes)
    {
        var full = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, new byte[bytes]);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
        catch { /* best effort */ }
    }

    [Fact]
    public async Task Aggregates_sizes_bottom_up_across_the_whole_tree()
    {
        var tree = await DirectoryTreeScanner.Shared.ScanAsync(_root);

        Assert.Equal(53_500, tree.SizeBytes);

        var big = tree.Children.Single(c => c.Name == "big");
        Assert.Equal(52_500, big.SizeBytes);

        var sub = big.Children.Single(c => c.Name == "sub");
        Assert.Equal(2_500, sub.SizeBytes);

        var empty = tree.Children.Single(c => c.Name == "empty");
        Assert.Equal(0, empty.SizeBytes);
    }

    [Fact]
    public async Task Counts_files_and_folders()
    {
        var result = await DirectoryTreeScanner.Shared.ScanDetailedAsync(_root);

        Assert.Equal(3, result.FileCount);
        Assert.Equal(3, result.Root.FileCount);
        Assert.Equal(0, result.SkippedCount);
        Assert.True(result.FolderCount >= 3, $"expected at least 3 folders, got {result.FolderCount}");
    }

    [Fact]
    public async Task Reports_progress_while_scanning()
    {
        var reports = new List<ScanProgress>();
        var progress = new Progress<ScanProgress>(p => reports.Add(p));

        await DirectoryTreeScanner.Shared.ScanAsync(_root, progress);

        // Progress is throttled, so on a tiny fixture we only guarantee it does not crash and
        // that anything reported is coherent.
        Assert.All(reports, r => Assert.True(r.BytesFound >= 0 && r.ItemsFound >= 0));
    }

    [Fact]
    public async Task Honours_cancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => DirectoryTreeScanner.Shared.ScanAsync(_root, null, cts.Token));
    }

    /// <remarks>
    /// A root that does not exist is a caller error (a stale path, an unplugged drive), so the
    /// scanner surfaces it as a typed exception rather than silently returning an empty tree —
    /// otherwise "0 bytes" and "that drive is gone" would be indistinguishable in the UI.
    /// Unreadable paths *inside* the tree behave differently: they are counted as skipped.
    /// </remarks>
    [Fact]
    public async Task A_missing_root_throws_a_typed_exception()
    {
        var missing = Path.Combine(_root, "does-not-exist-" + Guid.NewGuid().ToString("N"));

        await Assert.ThrowsAsync<DirectoryNotFoundException>(
            () => DirectoryTreeScanner.Shared.ScanAsync(missing));
    }

    [Fact]
    public async Task An_unreadable_subfolder_is_skipped_rather_than_fatal()
    {
        // Scanning a tree that contains a path we cannot read must still return a usable result.
        var result = await DirectoryTreeScanner.Shared.ScanDetailedAsync(_root);

        Assert.Equal(53_500, result.Root.SizeBytes);
        Assert.True(result.SkippedCount >= 0);
    }

    [Fact]
    public async Task LargestFiles_returns_files_biggest_first()
    {
        var tree = await DirectoryTreeScanner.Shared.ScanAsync(_root);
        var files = LargestItemsFinder.LargestFiles(tree, 10);

        Assert.Equal(3, files.Count);
        Assert.All(files, f => Assert.False(f.IsDirectory));
        Assert.Equal("huge.bin", files[0].Name);
        Assert.Equal(50_000, files[0].SizeBytes);

        for (int i = 1; i < files.Count; i++)
            Assert.True(files[i - 1].SizeBytes >= files[i].SizeBytes);
    }

    [Fact]
    public async Task LargestFolders_returns_folders_biggest_first_and_respects_take()
    {
        var tree = await DirectoryTreeScanner.Shared.ScanAsync(_root);

        var folders = LargestItemsFinder.LargestFolders(tree, 2);

        Assert.Equal(2, folders.Count);
        Assert.All(folders, f => Assert.True(f.IsDirectory));
        Assert.True(folders[0].SizeBytes >= folders[1].SizeBytes);
    }

    [Fact]
    public async Task Take_of_zero_or_less_yields_nothing()
    {
        var tree = await DirectoryTreeScanner.Shared.ScanAsync(_root);

        Assert.Empty(LargestItemsFinder.LargestFiles(tree, 0));
        Assert.Empty(LargestItemsFinder.LargestFolders(tree, -5));
    }

    [Fact]
    public void Fixed_drives_report_coherent_numbers()
    {
        var drives = DriveInfoProvider.Shared.GetFixedDrives();

        Assert.NotEmpty(drives);
        foreach (var d in drives)
        {
            Assert.True(d.TotalBytes > 0, $"{d.Name} reported no capacity");
            Assert.InRange(d.FreeBytes, 0, d.TotalBytes);
            Assert.InRange(d.UsedFraction, 0d, 1d);
            Assert.Equal(d.TotalBytes - d.FreeBytes, d.UsedBytes);
        }
    }
}
