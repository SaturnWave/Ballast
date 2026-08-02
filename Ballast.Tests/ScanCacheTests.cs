using System.Text;
using Ballast.Core.DiskAnalysis;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Exercises <see cref="ScanCache"/> against a temp cache folder, so nothing here touches the real
/// %LOCALAPPDATA% cache. Covers the round trip, and every way a cache is supposed to be refused:
/// too old, wrong format version, truncated, garbage.
/// </summary>
public sealed class ScanCacheTests : IDisposable
{
    private readonly string _temp;
    private readonly string _cacheFolder;
    private readonly string _fixtureRoot;
    private readonly ScanCache _cache;

    public ScanCacheTests()
    {
        _temp = Path.Combine(Path.GetTempPath(), "BallastScanCacheTests", Guid.NewGuid().ToString("N"));
        _cacheFolder = Path.Combine(_temp, "cache");
        _fixtureRoot = Path.Combine(_temp, "tree");

        Directory.CreateDirectory(_cacheFolder);

        // A small real tree, so one test can round-trip an actual scanner result:
        //   tree/
        //     a.bin            1000
        //     big/huge.bin    50000
        //     big/sub/c.bin    2500
        //     empty/
        Write("a.bin", 1000);
        Write(Path.Combine("big", "huge.bin"), 50_000);
        Write(Path.Combine("big", "sub", "c.bin"), 2_500);
        Directory.CreateDirectory(Path.Combine(_fixtureRoot, "empty"));

        _cache = new ScanCache(_cacheFolder);
    }

    private void Write(string relative, int bytes)
    {
        var full = Path.Combine(_fixtureRoot, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, new byte[bytes]);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_temp)) Directory.Delete(_temp, recursive: true); }
        catch { /* best effort */ }
    }

    // ------------------------------------------------------------ round trip

    [Fact]
    public async Task Round_trips_a_real_scan_node_for_node()
    {
        var scanned = await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot);

        await _cache.SaveAsync(_fixtureRoot, scanned);
        var loaded = await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1));

        Assert.NotNull(loaded);
        Assert.Equal(scanned.FolderCount, loaded.FolderCount);
        Assert.Equal(scanned.FileCount, loaded.FileCount);
        Assert.Equal(scanned.SkippedCount, loaded.SkippedCount);
        Assert.Equal(scanned.TotalBytes, loaded.TotalBytes);

        AssertSameTree(scanned.Root, loaded.Root);
    }

    /// <summary>
    /// The point of storing names only is that <see cref="DirNode.FullPath"/> has to be rebuilt from
    /// the parent chain, so this asserts the rebuilt paths are the real ones on disk.
    /// </summary>
    [Fact]
    public async Task Reconstructed_full_paths_still_point_at_the_real_files()
    {
        var scanned = await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot);
        await _cache.SaveAsync(_fixtureRoot, scanned);

        var loaded = await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1));

        Assert.NotNull(loaded);
        Assert.Equal(Path.GetFullPath(_fixtureRoot), loaded.Root.FullPath);

        foreach (var node in Flatten(loaded.Root))
        {
            Assert.True(
                node.IsDirectory ? Directory.Exists(node.FullPath) : File.Exists(node.FullPath),
                $"rebuilt path does not exist: {node.FullPath}");
        }

        var huge = Flatten(loaded.Root).Single(n => n.Name == "huge.bin");
        Assert.Equal(Path.Combine(_fixtureRoot, "big", "huge.bin"), huge.FullPath);
        Assert.Equal(50_000, huge.SizeBytes);
    }

    [Fact]
    public async Task Round_trips_names_sizes_counts_and_parent_links()
    {
        var root = SyntheticTree(@"C:\SynthRoot");
        var result = new TreeScanResult(root, SkippedCount: 7, FolderCount: 4, FileCount: 3);

        await _cache.SaveAsync(@"C:\SynthRoot", result);
        var loaded = await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1));

        Assert.NotNull(loaded);
        Assert.Equal(7, loaded.SkippedCount);
        Assert.True(loaded.IsPartial);
        Assert.Equal(4, loaded.FolderCount);
        Assert.Equal(3, loaded.FileCount);
        Assert.InRange(loaded.Age, TimeSpan.Zero, TimeSpan.FromMinutes(5));

        AssertSameTree(root, loaded.Root);

        // Parent links are not stored either; they are rebuilt while reading.
        Assert.Null(loaded.Root.Parent);

        var docs = loaded.Root.Children.Single(c => c.Name == "Docs");
        Assert.Same(loaded.Root, docs.Parent);
        Assert.Equal(@"C:\SynthRoot\Docs", docs.FullPath);

        var notes = docs.Children.Single(c => c.Name == "notes.txt");
        Assert.Same(docs, notes.Parent);
        Assert.False(notes.IsDirectory);
        Assert.Equal(@"C:\SynthRoot\Docs\notes.txt", notes.FullPath);
        Assert.Equal(2_048, notes.SizeBytes);
    }

    /// <summary>
    /// Both the writer and the reader walk with an explicit stack, so a chain like this cannot
    /// overflow the real one. Written recursively, this is where it would fall over. (Depth is
    /// capped by the fact that every level makes the rebuilt path longer, so the tree itself costs
    /// quadratic memory to hold — nothing to do with the format.)
    /// </summary>
    [Fact]
    public async Task Survives_a_tree_far_deeper_than_a_recursive_walk_would_manage()
    {
        const int depth = 3_000;

        var root = new DirNode { Name = "deep", FullPath = @"C:\Deep", IsDirectory = true };
        var leaf = root;
        for (int i = 0; i < depth; i++)
        {
            var child = new DirNode
            {
                Name = "n",
                FullPath = Path.Combine(leaf.FullPath, "n"),
                IsDirectory = true,
                SizeBytes = 1,
                Parent = leaf,
            };
            leaf.Children.Add(child);
            leaf = child;
        }

        await _cache.SaveAsync(@"C:\Deep", new TreeScanResult(root, 0, depth + 1, 0));
        var loaded = await _cache.TryLoadAsync(@"C:\Deep", TimeSpan.FromHours(1));

        Assert.NotNull(loaded);

        var node = loaded.Root;
        int seen = 0;
        while (node.Children.Count > 0)
        {
            node = Assert.Single(node.Children);
            seen++;
        }

        Assert.Equal(depth, seen);
        Assert.Equal("n", node.Name);
        Assert.Equal(leaf.FullPath, node.FullPath);
    }

    [Fact]
    public async Task Separate_roots_get_separate_files_and_never_collide()
    {
        var c = SyntheticTree(@"C:\");
        var d = SyntheticTree(@"D:\");
        d.SizeBytes = 999;

        await _cache.SaveAsync(@"C:\", new TreeScanResult(c, 0, 4, 3));
        await _cache.SaveAsync(@"D:\", new TreeScanResult(d, 0, 4, 3));

        Assert.NotEqual(_cache.CacheFilePath(@"C:\"), _cache.CacheFilePath(@"D:\"));
        Assert.Equal(2, Directory.GetFiles(_cacheFolder, "*.bin").Length);

        var loadedC = await _cache.TryLoadAsync(@"C:\", TimeSpan.FromHours(1));
        var loadedD = await _cache.TryLoadAsync(@"D:\", TimeSpan.FromHours(1));

        Assert.NotNull(loadedC);
        Assert.NotNull(loadedD);
        Assert.Equal(c.SizeBytes, loadedC.Root.SizeBytes);
        Assert.Equal(999, loadedD.Root.SizeBytes);
    }

    [Fact]
    public async Task The_saved_file_is_much_smaller_than_the_paths_it_describes()
    {
        // Names-only plus gzip: a tree whose paths alone run to hundreds of KB has to land well
        // under that, or the format is not earning its keep.
        var root = new DirNode { Name = "big", FullPath = @"C:\Big", IsDirectory = true };
        long pathBytes = root.FullPath.Length;

        for (int i = 0; i < 200; i++)
        {
            var folder = new DirNode
            {
                Name = $"folder-number-{i}",
                FullPath = Path.Combine(root.FullPath, $"folder-number-{i}"),
                IsDirectory = true,
                Parent = root,
            };
            root.Children.Add(folder);
            pathBytes += folder.FullPath.Length;

            for (int j = 0; j < 50; j++)
            {
                var file = new DirNode
                {
                    Name = $"a-reasonably-long-file-name-{j}.bin",
                    FullPath = Path.Combine(folder.FullPath, $"a-reasonably-long-file-name-{j}.bin"),
                    SizeBytes = 4096,
                    FileCount = 1,
                    Parent = folder,
                };
                folder.Children.Add(file);
                pathBytes += file.FullPath.Length;
            }
        }

        await _cache.SaveAsync(@"C:\Big", new TreeScanResult(root, 0, 201, 10_000));

        var size = new FileInfo(_cache.CacheFilePath(@"C:\Big")).Length;

        Assert.True(size * 10 < pathBytes, $"cache is {size} bytes for {pathBytes} bytes of paths");
        Assert.NotNull(await _cache.TryLoadAsync(@"C:\Big", TimeSpan.FromHours(1)));
    }

    // --------------------------------------------------------------- refusal

    [Fact]
    public async Task A_missing_cache_is_null_not_an_exception()
    {
        var loaded = await _cache.TryLoadAsync(@"C:\NeverScanned", TimeSpan.FromHours(1));

        Assert.Null(loaded);
    }

    [Fact]
    public async Task A_cache_older_than_maxAge_is_refused_but_kept()
    {
        await _cache.SaveAsync(@"C:\SynthRoot", Result());

        var stale = await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.Zero);

        Assert.Null(stale);

        // Stale is not broken: the file stays put, and a generous maxAge still reads it.
        Assert.True(File.Exists(_cache.CacheFilePath(@"C:\SynthRoot")));
        Assert.NotNull(await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1)));
    }

    [Fact]
    public async Task A_cache_written_by_another_format_version_is_refused_and_binned()
    {
        await _cache.SaveAsync(@"C:\SynthRoot", Result());
        var path = _cache.CacheFilePath(@"C:\SynthRoot");

        // Header layout: uint magic, then int format version. Poke a version this build cannot read.
        var bytes = File.ReadAllBytes(path);
        BitConverter.GetBytes(9999).CopyTo(bytes, 4);
        File.WriteAllBytes(path, bytes);

        Assert.Null(await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path), "an unreadable format should be deleted, not left to be re-read");
    }

    [Fact]
    public async Task A_file_that_is_not_a_scan_cache_at_all_is_refused_and_binned()
    {
        await _cache.SaveAsync(@"C:\SynthRoot", Result());
        var path = _cache.CacheFilePath(@"C:\SynthRoot");

        File.WriteAllBytes(path, Encoding.UTF8.GetBytes("this is definitely not a scan cache"));

        Assert.Null(await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path));
    }

    /// <summary>Cut the file off at several points — empty, mid-header, mid-payload, and a few
    /// bytes short of the end — and none of them may produce a tree or an exception.</summary>
    [Theory]
    [InlineData(0.0)]
    [InlineData(0.02)]
    [InlineData(0.5)]
    [InlineData(0.95)]
    public async Task A_truncated_cache_is_refused_and_binned(double keepFraction)
    {
        await _cache.SaveAsync(_fixtureRoot, await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot));
        var path = _cache.CacheFilePath(_fixtureRoot);

        var bytes = File.ReadAllBytes(path);
        File.WriteAllBytes(path, bytes[..(int)(bytes.Length * keepFraction)]);

        Assert.Null(await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path), "a truncated cache should be deleted, not retried forever");
    }

    /// <summary>
    /// The sharp edge of the same case: a gzip stream missing only its trailer still inflates
    /// perfectly well, so nothing but the recorded payload length notices this.
    /// </summary>
    [Fact]
    public async Task A_cache_one_byte_short_is_refused_and_binned()
    {
        await _cache.SaveAsync(_fixtureRoot, await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot));
        var path = _cache.CacheFilePath(_fixtureRoot);

        var bytes = File.ReadAllBytes(path);
        File.WriteAllBytes(path, bytes[..^1]);

        Assert.Null(await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task A_cache_with_bytes_appended_is_refused_and_binned()
    {
        await _cache.SaveAsync(_fixtureRoot, await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot));
        var path = _cache.CacheFilePath(_fixtureRoot);

        File.AppendAllText(path, "extra");

        Assert.Null(await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task A_corrupted_payload_is_refused_rather_than_mis_parsed()
    {
        await _cache.SaveAsync(_fixtureRoot, await DirectoryTreeScanner.Shared.ScanDetailedAsync(_fixtureRoot));
        var path = _cache.CacheFilePath(_fixtureRoot);

        // Flip bits well inside the deflate stream. Either the gzip CRC or our own end sentinel
        // has to catch this; what must not happen is a plausible-looking wrong tree.
        var bytes = File.ReadAllBytes(path);
        for (int i = bytes.Length / 2; i < bytes.Length - 4; i++) bytes[i] ^= 0x5A;
        File.WriteAllBytes(path, bytes);

        Assert.Null(await _cache.TryLoadAsync(_fixtureRoot, TimeSpan.FromHours(1)));
        Assert.False(File.Exists(path));
    }

    // ------------------------------------------------------------ invalidate

    [Fact]
    public async Task Invalidate_removes_the_cache()
    {
        await _cache.SaveAsync(@"C:\SynthRoot", Result());
        Assert.True(File.Exists(_cache.CacheFilePath(@"C:\SynthRoot")));

        _cache.Invalidate(@"C:\SynthRoot");

        Assert.False(File.Exists(_cache.CacheFilePath(@"C:\SynthRoot")));
        Assert.Null(await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1)));
    }

    [Fact]
    public void Invalidating_something_never_cached_is_a_no_op()
    {
        _cache.Invalidate(@"C:\NeverScanned");
        _cache.Invalidate(@"Z:\GoneDrive\Whatever");
    }

    [Fact]
    public async Task Saving_twice_replaces_rather_than_accumulates()
    {
        await _cache.SaveAsync(@"C:\SynthRoot", Result());

        var second = SyntheticTree(@"C:\SynthRoot");
        second.SizeBytes = 123_456;
        await _cache.SaveAsync(@"C:\SynthRoot", new TreeScanResult(second, 0, 4, 3));

        Assert.Single(Directory.GetFiles(_cacheFolder, "*.bin"));
        Assert.Empty(Directory.GetFiles(_cacheFolder, "*.tmp"));

        var loaded = await _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1));

        Assert.NotNull(loaded);
        Assert.Equal(123_456, loaded.Root.SizeBytes);
    }

    // ------------------------------------------------------- argument checks

    [Fact]
    public async Task A_blank_root_is_a_caller_error()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _cache.SaveAsync("  ", Result()));
        await Assert.ThrowsAsync<ArgumentException>(() => _cache.TryLoadAsync("", TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentException>(() => _cache.Invalidate("   "));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _cache.SaveAsync(@"C:\SynthRoot", null!));
    }

    [Fact]
    public async Task Honours_cancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _cache.SaveAsync(@"C:\SynthRoot", Result(), cts.Token));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _cache.TryLoadAsync(@"C:\SynthRoot", TimeSpan.FromHours(1), cts.Token));
    }

    [Fact]
    public void The_default_cache_folder_sits_under_local_appdata()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.StartsWith(local, ScanCache.CacheFolder, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(Path.Combine("Ballast", "cache"), ScanCache.CacheFolder, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- helpers

    private TreeScanResult Result() => new(SyntheticTree(@"C:\SynthRoot"), 0, 4, 3);

    /// <summary>
    /// A hand-built tree with the same aggregate discipline the scanner produces:
    /// <code>
    /// SynthRoot                 53_248
    ///   Docs                     2_048
    ///     notes.txt              2_048
    ///   Media                   51_200
    ///     clip.mp4              51_200
    ///   Empty                        0
    ///   loose.bin                    0
    /// </code>
    /// </summary>
    private static DirNode SyntheticTree(string rootFullPath)
    {
        var root = new DirNode
        {
            Name = Path.GetFileName(rootFullPath.TrimEnd('\\')) is { Length: > 0 } leaf ? leaf : rootFullPath,
            FullPath = rootFullPath,
            IsDirectory = true,
            SizeBytes = 53_248,
            FileCount = 3,
        };

        var docs = AddFolder(root, "Docs", 2_048, 1);
        AddFile(docs, "notes.txt", 2_048);

        var media = AddFolder(root, "Media", 51_200, 1);
        AddFile(media, "clip.mp4", 51_200);

        AddFolder(root, "Empty", 0, 0);
        AddFile(root, "loose.bin", 0);

        return root;
    }

    private static DirNode AddFolder(DirNode parent, string name, long size, long files)
    {
        var node = new DirNode
        {
            Name = name,
            FullPath = Path.Combine(parent.FullPath, name),
            IsDirectory = true,
            SizeBytes = size,
            FileCount = files,
            Parent = parent,
        };

        parent.Children.Add(node);
        return node;
    }

    private static void AddFile(DirNode parent, string name, long size) =>
        parent.Children.Add(new DirNode
        {
            Name = name,
            FullPath = Path.Combine(parent.FullPath, name),
            IsDirectory = false,
            SizeBytes = size,
            FileCount = 1,
            Parent = parent,
        });

    private static IEnumerable<DirNode> Flatten(DirNode root)
    {
        var stack = new Stack<DirNode>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var node = stack.Pop();
            yield return node;

            foreach (var child in node.Children) stack.Push(child);
        }
    }

    /// <summary>Compares two trees exhaustively: order, names, paths, sizes, counts, parent links.</summary>
    private static void AssertSameTree(DirNode expected, DirNode actual)
    {
        Assert.Equal(expected.Name, actual.Name);
        Assert.Equal(expected.FullPath, actual.FullPath);
        Assert.Equal(expected.SizeBytes, actual.SizeBytes);
        Assert.Equal(expected.FileCount, actual.FileCount);
        Assert.Equal(expected.IsDirectory, actual.IsDirectory);
        Assert.Equal(expected.Children.Count, actual.Children.Count);

        for (int i = 0; i < expected.Children.Count; i++)
        {
            Assert.Same(actual, actual.Children[i].Parent);
            AssertSameTree(expected.Children[i], actual.Children[i]);
        }
    }
}
