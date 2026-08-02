using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Ballast.Core.DiskAnalysis;

/// <summary>
/// A tree that came back from <see cref="ScanCache"/> instead of from a fresh walk of the disk.
/// </summary>
/// <param name="Root">The reconstructed tree. Identical in shape and numbers to what was saved.</param>
/// <param name="ScannedAt">When the original scan finished (UTC). This is how old the numbers are.</param>
/// <param name="FolderCount">Folders the original scan visited.</param>
/// <param name="FileCount">Files the original scan measured.</param>
/// <param name="SkippedCount">Entries the original scan could not read.</param>
/// <remarks>
/// The sizes are a snapshot: the disk has almost certainly moved on since <see cref="ScannedAt"/>.
/// Show the age in the UI so nobody deletes something on the strength of a week-old number.
/// </remarks>
public sealed record CachedScan(
    DirNode Root,
    DateTimeOffset ScannedAt,
    long FolderCount,
    long FileCount,
    int SkippedCount)
{
    /// <summary>Total bytes the cached scan measured.</summary>
    public long TotalBytes => Root.SizeBytes;

    /// <summary>True when the original scan could not read part of the tree.</summary>
    public bool IsPartial => SkippedCount > 0;

    /// <summary>How long ago the original scan ran. Never negative unless the clock moved backwards.</summary>
    public TimeSpan Age => DateTimeOffset.UtcNow - ScannedAt;

    /// <summary>
    /// Reshapes this into the same record a live scan produces, so a caller can feed cached and
    /// fresh results through one code path.
    /// </summary>
    public TreeScanResult ToScanResult() => new(Root, SkippedCount, FolderCount, FileCount);
}

/// <summary>
/// Persists the result of a <see cref="DirectoryTreeScanner"/> walk to disk and reads it back, so
/// opening the app twice in an afternoon does not mean walking the whole drive twice.
///
/// <para><strong>Be honest about what this buys.</strong> Two things were wanted — skip the rescan,
/// and use less RAM. This delivers the first outright and only part of the second:</para>
/// <list type="bullet">
///   <item><description>
///     <em>The rescan goes away.</em> A whole-of-C: walk is minutes of I/O; reading this file back
///     is a fraction of a second. That is the real win.
///   </description></item>
///   <item><description>
///     <em>Memory between sessions goes away</em> — you no longer have to keep a tree alive (or
///     rebuild it) just to have one. On disk the same tree is a few MB rather than hundreds:
///     each node stores its <em>name only</em>, and the whole payload is gzipped.
///   </description></item>
///   <item><description>
///     <em>Resident memory during a session is unchanged.</em> <see cref="TryLoadAsync"/> hands back
///     a fully materialised tree — one <see cref="DirNode"/> per node, and every
///     <see cref="DirNode.FullPath"/> rebuilt as a real string. A million-node tree costs about the
///     same RAM loaded as it did scanned. Nothing here makes a big tree small in memory.
///   </description></item>
/// </list>
/// <para>
/// Cutting the resident cost would take a different shape entirely, and is deliberately not
/// attempted here: an on-disk index (a byte offset per node) so children are read only when a
/// folder is actually expanded, plus flat arrays and an interned name table instead of a linked
/// object graph. That means <see cref="DirNode.Children"/> can no longer be a plain
/// <see cref="List{T}"/>, so it is a change to the model and every consumer of it, not a change to
/// this file.
/// </para>
/// </summary>
/// <remarks>
/// <para>
/// The format is hand-rolled over <see cref="BinaryWriter"/> rather than JSON: a million nodes of
/// JSON is tens of seconds and hundreds of MB. Layout is a plain (uncompressed) header — magic,
/// format version, root path, timestamp, counts, payload length — followed by a gzipped,
/// depth-first pre-order dump of the tree, ended by a sentinel and a node count. Keeping the
/// header uncompressed lets a stale, foreign, or truncated cache be rejected without inflating a
/// single byte of the payload.
/// </para>
/// <para>
/// Nothing here throws for an I/O or corruption reason. A cache that is missing, locked, truncated,
/// garbled, or written by another build degrades to "just scan again", never to a crash. Only a
/// caller mistake (a blank or unusable path) and cancellation surface as exceptions.
/// </para>
/// </remarks>
public sealed class ScanCache
{
    /// <summary>Shared instance for callers that are not using dependency injection. Thread-safe.</summary>
    public static ScanCache Shared { get; } = new();

    /// <summary>First four bytes of every cache file: "CMWS".</summary>
    private const uint FileMagic = 0x53574D43;

    /// <summary>Sentinel written after the last node: "CEND". Proves the payload arrived whole.</summary>
    private const uint EndMagic = 0x444E4543;

    /// <summary>
    /// Bump this whenever the byte layout changes. A file written by any other version is refused
    /// and deleted rather than parsed — misreading a tree is far worse than rescanning one.
    /// </summary>
    private const int FormatVersion = 1;

    /// <summary>Longest string the reader will allocate for. Real names cap out around 1 KB.</summary>
    private const int MaxStringBytes = 128 * 1024;

    /// <summary>Reused encode buffer; comfortably larger than any Windows path component.</summary>
    private const int ScratchBytes = 1024;

    /// <summary>Cancellation is polled every this-many nodes (a power of two, used as a mask).</summary>
    private const long CancellationMask = 4095;

    /// <summary>Abandoned temp files older than this are swept on the next save.</summary>
    private static readonly TimeSpan TempFileLifetime = TimeSpan.FromHours(1);

    /// <summary>
    /// Default location of the cache: <c>%LOCALAPPDATA%\Ballast\cache</c>. Per-user, roams
    /// nowhere, and is safe to delete by hand at any time.
    /// </summary>
    public static string CacheFolder { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ballast", "cache");

    /// <summary>
    /// Creates a cache. <paramref name="cacheFolder"/> exists so tests can work in a temp folder;
    /// leave it null in the app to get <see cref="CacheFolder"/>.
    /// </summary>
    public ScanCache(string? cacheFolder = null) =>
        Folder = string.IsNullOrWhiteSpace(cacheFolder) ? CacheFolder : Path.GetFullPath(cacheFolder);

    /// <summary>Folder this instance reads and writes. Usually <see cref="CacheFolder"/>.</summary>
    public string Folder { get; }

    /// <summary>
    /// Where the cache for <paramref name="rootPath"/> lives. One file per root, named from a hash
    /// of the normalised path, so <c>C:\</c> and <c>D:\</c> can never land on the same file.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is blank or unusable.</exception>
    public string CacheFilePath(string rootPath) =>
        Path.Combine(Folder, $"scan-{Fingerprint(Normalise(rootPath))}.bin");

    /// <summary>
    /// Writes <paramref name="result"/> to disk on a background thread, replacing any previous cache
    /// for <paramref name="rootPath"/>.
    ///
    /// <para>
    /// The file is built under a temporary name and moved into place, so a crash mid-write leaves
    /// the previous cache intact rather than a half-written one. If the write fails for any I/O
    /// reason the task still completes successfully — a cache that could not be saved is a lost
    /// optimisation, not an error the user needs to hear about.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="result"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is blank or unusable.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> fired.</exception>
    public Task SaveAsync(string rootPath, TreeScanResult result, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var root = Normalise(rootPath);

        return Task.Run(() => Save(root, result, ct), ct);
    }

    /// <summary>
    /// Reads back the cache for <paramref name="rootPath"/> on a background thread, or returns
    /// <see langword="null"/> when there is nothing usable to read.
    ///
    /// <para>Null means "scan it yourself", and covers every one of:</para>
    /// <list type="bullet">
    ///   <item><description>no cache file for this root;</description></item>
    ///   <item><description>the cache is older than <paramref name="maxAge"/> (the file is left alone —
    ///     stale is not broken, and the next save overwrites it);</description></item>
    ///   <item><description>it was written by a different <c>FormatVersion</c>, is truncated, or is
    ///     corrupt (the file is deleted);</description></item>
    ///   <item><description>it is locked or unreadable right now (the file is left alone).</description></item>
    /// </list>
    /// <para>
    /// A returned tree is fully in memory, exactly as a fresh scan would be — see the type remarks.
    /// It is also a snapshot: check <see cref="CachedScan.Age"/> before showing it as current.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is blank or unusable.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> fired.</exception>
    public Task<CachedScan?> TryLoadAsync(string rootPath, TimeSpan maxAge, CancellationToken ct = default)
    {
        var root = Normalise(rootPath);

        return Task.Run(() => Load(root, maxAge, ct), ct);
    }

    /// <summary>
    /// Drops the cache for <paramref name="rootPath"/>. Call it after anything that makes the saved
    /// numbers a lie — a cleanup run, a delete, a restore. Silent when there is no cache to drop.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is blank or unusable.</exception>
    public void Invalidate(string rootPath) => TryDelete(CacheFilePath(rootPath));

    // ---------------------------------------------------------------- write

    private void Save(string rootPath, TreeScanResult result, CancellationToken ct)
    {
        var target = CacheFilePath(rootPath);
        var temp = $"{target}.{Guid.NewGuid():N}.tmp";

        try
        {
            Directory.CreateDirectory(Folder);
            SweepAbandonedTemporaries(Folder);

            using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                // The tree carries its own idea of where it came from; prefer it, so the paths we
                // rebuild on load are byte-for-byte the ones the scanner produced.
                var storedRoot = string.IsNullOrEmpty(result.Root.FullPath) ? rootPath : result.Root.FullPath;
                var scratch = new byte[ScratchBytes];

                long lengthSlot;

                using (var header = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true))
                {
                    header.Write(FileMagic);
                    header.Write(FormatVersion);
                    WriteString(header, storedRoot, scratch);
                    header.Write(DateTimeOffset.UtcNow.UtcTicks);
                    header.Write(result.FolderCount);
                    header.Write(result.FileCount);
                    header.Write(result.SkippedCount);

                    // Patched once the payload is written. It is the only reliable way to notice a
                    // truncated file up front: a gzip stream missing its trailer still inflates.
                    lengthSlot = file.Position;
                    header.Write(0L);
                }

                long payloadStart = file.Position;

                // Fastest, not Optimal: this runs at the end of every scan, and the data is so
                // repetitive that the cheap level already removes the great majority of the bytes.
                using (var gzip = new GZipStream(file, CompressionLevel.Fastest, leaveOpen: true))
                using (var body = new BinaryWriter(gzip, Encoding.UTF8, leaveOpen: true))
                {
                    WriteTree(body, result.Root, scratch, ct);
                }

                long payloadBytes = file.Position - payloadStart;

                using (var patch = new BinaryWriter(file, Encoding.UTF8, leaveOpen: true))
                {
                    file.Position = lengthSlot;
                    patch.Write(payloadBytes);
                }
            }

            File.Move(temp, target, overwrite: true);
            temp = string.Empty;
        }
        catch (Exception ex) when (IsTransient(ex))
        {
            // Saving the cache is best-effort: the scan itself already succeeded.
        }
        finally
        {
            if (temp.Length > 0) TryDelete(temp);
        }
    }

    /// <summary>
    /// Depth-first pre-order, iteratively. Recursion is not an option: these trees go as deep as
    /// the filesystem allows and a stack overflow cannot be caught.
    /// </summary>
    private static void WriteTree(BinaryWriter writer, DirNode root, byte[] scratch, CancellationToken ct)
    {
        var stack = new Stack<DirNode>();
        stack.Push(root);

        long written = 0;

        while (stack.Count > 0)
        {
            if ((written & CancellationMask) == 0) ct.ThrowIfCancellationRequested();

            var node = stack.Pop();
            var children = node.Children;

            WriteString(writer, node.Name, scratch);
            writer.Write(node.IsDirectory);

            // Clamped because a negative would cost ten bytes to encode and cannot be real.
            writer.Write7BitEncodedInt64(Math.Max(0, node.SizeBytes));
            writer.Write7BitEncodedInt64(Math.Max(0, node.FileCount));
            writer.Write7BitEncodedInt(children.Count);

            written++;

            // Pushed backwards so they come off the stack — and land in the file — in order.
            for (int i = children.Count - 1; i >= 0; i--) stack.Push(children[i]);
        }

        writer.Write(EndMagic);
        writer.Write7BitEncodedInt64(written);
    }

    // ----------------------------------------------------------------- read

    private CachedScan? Load(string rootPath, TimeSpan maxAge, CancellationToken ct)
    {
        var path = CacheFilePath(rootPath);

        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);

            return Read(file, rootPath, maxAge, ct);
        }
        catch (Exception ex) when (IsCorruption(ex))
        {
            // Fall through and bin it. Ordering matters: EndOfStreamException is an IOException,
            // so this filter has to sit above the transient one.
        }
        catch (Exception ex) when (IsTransient(ex))
        {
            // Missing, locked, or unreadable this instant. Keep the file and just scan.
            return null;
        }

        TryDelete(path); // the stream is closed by now, so this succeeds
        return null;
    }

    private static CachedScan? Read(Stream file, string rootPath, TimeSpan maxAge, CancellationToken ct)
    {
        string storedRoot;
        long ticks;
        long folderCount;
        long fileCount;
        int skippedCount;
        long payloadBytes;

        using (var header = new BinaryReader(file, Encoding.UTF8, leaveOpen: true))
        {
            if (header.ReadUInt32() != FileMagic)
                throw new InvalidDataException("Not a Ballast scan cache.");

            int version = header.ReadInt32();
            if (version != FormatVersion)
                throw new InvalidDataException($"Scan cache is format {version}; this build reads {FormatVersion}.");

            storedRoot = ReadString(header);
            ticks = header.ReadInt64();
            folderCount = header.ReadInt64();
            fileCount = header.ReadInt64();
            skippedCount = header.ReadInt32();
            payloadBytes = header.ReadInt64();
        }

        // Cheapest possible integrity check, and the surest: a truncated gzip stream can still
        // inflate happily, so the byte count is what actually catches a half-written file.
        if (payloadBytes < 0 || file.Length - file.Position != payloadBytes)
            throw new InvalidDataException("Scan cache is truncated or has trailing bytes.");

        if (ticks < 0 || ticks > DateTime.MaxValue.Ticks)
            throw new InvalidDataException("Scan cache carries an impossible timestamp.");

        if (folderCount < 0 || fileCount < 0 || skippedCount < 0)
            throw new InvalidDataException("Scan cache carries negative counts.");

        if (storedRoot.Length == 0)
            throw new InvalidDataException("Scan cache names no root.");

        // Belt and braces against a hash collision, or a cache file copied in from elsewhere: the
        // payload would describe a different tree, so it is not ours to hand back.
        if (!Key(storedRoot).Equals(Key(rootPath), StringComparison.Ordinal)) return null;

        var scannedAt = new DateTimeOffset(ticks, TimeSpan.Zero);

        // Checked before a single byte is inflated. A clock that moved backwards makes the age
        // negative, which counts as fresh — deliberately, so a DST or NTP nudge cannot throw away
        // a scan that is genuinely minutes old.
        if (DateTimeOffset.UtcNow - scannedAt > maxAge) return null;

        using var gzip = new GZipStream(file, CompressionMode.Decompress, leaveOpen: true);
        using var body = new BinaryReader(gzip, Encoding.UTF8, leaveOpen: true);

        var root = ReadTree(body, storedRoot, ct);

        // Draining to EOF is what makes GZipStream verify its CRC over everything just parsed.
        // Together with the sentinel above, a silently mis-parsed tree is not really possible.
        if (gzip.ReadByte() != -1)
            throw new InvalidDataException("Scan cache has trailing data.");

        return new CachedScan(root, scannedAt, folderCount, fileCount, skippedCount);
    }

    /// <summary>
    /// Mirror image of <see cref="WriteTree"/>: iterative, with an explicit stack of
    /// (parent, children still owed) so a deep tree cannot overflow the real one.
    /// </summary>
    private static DirNode ReadTree(BinaryReader reader, string rootFullPath, CancellationToken ct)
    {
        var (root, rootChildren) = ReadNode(reader, parent: null, rootFullPath);

        var stack = new Stack<(DirNode Parent, int Remaining)>();
        if (rootChildren > 0) stack.Push((root, rootChildren));

        long read = 1;

        while (stack.Count > 0)
        {
            if ((read & CancellationMask) == 0) ct.ThrowIfCancellationRequested();

            var (parent, remaining) = stack.Pop();
            if (remaining > 1) stack.Push((parent, remaining - 1));

            var (child, grandchildren) = ReadNode(reader, parent, null);
            parent.Children.Add(child);
            read++;

            // On top of the parent frame, so this child's whole subtree is consumed first.
            if (grandchildren > 0) stack.Push((child, grandchildren));
        }

        if (reader.ReadUInt32() != EndMagic)
            throw new InvalidDataException("Scan cache is truncated or damaged.");

        if (reader.Read7BitEncodedInt64() != read)
            throw new InvalidDataException("Scan cache node count disagrees with its tree.");

        return root;
    }

    private static (DirNode Node, int ChildCount) ReadNode(BinaryReader reader, DirNode? parent, string? rootFullPath)
    {
        var name = ReadString(reader);
        bool isDirectory = reader.ReadBoolean();
        long size = reader.Read7BitEncodedInt64();
        long files = reader.Read7BitEncodedInt64();
        int children = reader.Read7BitEncodedInt();

        if (size < 0 || files < 0 || children < 0)
            throw new InvalidDataException("Scan cache node carries a negative count.");

        var node = new DirNode
        {
            Name = name,
            // Full paths are never stored — rebuilding them from the parent chain is what removes
            // most of the bytes, since every child otherwise repeats its parent in full.
            FullPath = rootFullPath ?? Path.Combine(parent!.FullPath, name),
            IsDirectory = isDirectory,
            SizeBytes = size,
            FileCount = files,
            Parent = parent,
        };

        return (node, children);
    }

    // ------------------------------------------------------------- plumbing

    /// <summary>Length-prefixed UTF-8. Hand-rolled so the reader can reject an absurd length
    /// before allocating for it — <see cref="BinaryReader.ReadString"/> allocates first.</summary>
    private static void WriteString(BinaryWriter writer, string value, byte[] scratch)
    {
        int count = Encoding.UTF8.GetByteCount(value);

        if (count <= scratch.Length)
        {
            Encoding.UTF8.GetBytes(value.AsSpan(), scratch.AsSpan());
            writer.Write7BitEncodedInt(count);
            writer.Write(scratch, 0, count);
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        writer.Write7BitEncodedInt(bytes.Length);
        writer.Write(bytes);
    }

    private static string ReadString(BinaryReader reader)
    {
        int count = reader.Read7BitEncodedInt();

        if ((uint)count > MaxStringBytes)
            throw new InvalidDataException("Scan cache declares an impossible string length.");

        if (count == 0) return string.Empty;

        var bytes = reader.ReadBytes(count);
        if (bytes.Length != count) throw new EndOfStreamException();

        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Normalises for comparison and hashing: no trailing separator, case-insensitive.</summary>
    private static string Key(string fullPath)
    {
        var trimmed = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return (trimmed.Length > 0 ? trimmed : fullPath).ToUpperInvariant();
    }

    /// <summary>
    /// Stable 64-bit fingerprint of a root path. SHA-256 rather than <see cref="string.GetHashCode()"/>,
    /// which is salted per process and would name a different file on every launch.
    /// </summary>
    private static string Fingerprint(string fullPath)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(Key(fullPath)), digest);

        return Convert.ToHexString(digest[..8]);
    }

    private static string Normalise(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);

        try
        {
            return Path.GetFullPath(rootPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArgumentException($"'{rootPath}' is not a usable path.", nameof(rootPath), ex);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // Deleting a cache file is always best-effort; the next save replaces it anyway.
        }
    }

    /// <summary>
    /// Clears temp files left behind by a process that died mid-save. A disk-cleaning app has no
    /// business leaking files of its own.
    /// </summary>
    private static void SweepAbandonedTemporaries(string folder)
    {
        try
        {
            var cutoff = DateTime.UtcNow - TempFileLifetime;

            foreach (var stale in Directory.EnumerateFiles(folder, "*.tmp"))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(stale) < cutoff) File.Delete(stale);
                }
                catch
                {
                    // Someone else's file, or in use. Leave it.
                }
            }
        }
        catch
        {
            // Housekeeping must never affect the save that triggered it.
        }
    }

    /// <summary>A cache file that cannot be believed: truncated, garbled, or a foreign format.</summary>
    private static bool IsCorruption(Exception ex) =>
        ex is EndOfStreamException or InvalidDataException or FormatException;

    /// <summary>Ordinary filesystem trouble: absent, locked, denied. Says nothing about the contents.</summary>
    private static bool IsTransient(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or System.Security.SecurityException;
}
