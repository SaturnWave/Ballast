using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace Ballast.Core.Util;

/// <summary>
/// Pulls the icon out of a program on disk and hands it back as PNG bytes, so a list of programs
/// can show what each one actually is instead of a row of identical glyphs.
///
/// <para>
/// Everything here treats an icon as <em>decoration</em>. No input is trusted, no failure is
/// reported, and nothing is allowed to make a scan slower or less reliable:
/// </para>
/// <list type="bullet">
/// <item>Every guard returns <see langword="null"/> rather than throwing, including the catch-all
/// around the native calls. A caller can ignore the result entirely and still be correct.</item>
/// <item>Cloud placeholders are skipped, because reading an icon out of a dehydrated file makes
/// the sync client download the whole thing.</item>
/// <item>UNC and network paths are skipped, because a dead share can block for its full timeout
/// and no icon is worth that.</item>
/// <item>Results are cached per session, so rebuilding a list does not re-read the same binaries.</item>
/// </list>
///
/// <para>
/// PNG is produced by hand (see <see cref="EncodePng"/>) rather than through
/// <c>System.Drawing</c>: that assembly is not in this project's framework reference set, and a
/// 60-line encoder is a smaller cost than a dependency.
/// </para>
/// </summary>
public static class FileIconExtractor
{
    /// <summary>Smallest icon worth asking for.</summary>
    private const int MinSize = 8;

    /// <summary>Largest icon worth asking for; beyond this the shell has nothing better to give.</summary>
    private const int MaxSize = 256;

    /// <summary>
    /// Ceiling on cached entries. A startup list has tens of programs, not thousands; the cap only
    /// exists so a pathological caller cannot grow this without bound.
    /// </summary>
    private const int MaxCacheEntries = 512;

    /// <summary>
    /// Extracted PNGs (and cached misses, as <see langword="null"/>) keyed by size and full path.
    /// Concurrent because several rows may be filled in from different threads.
    /// </summary>
    private static readonly ConcurrentDictionary<string, byte[]?> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly uint[] CrcTable = BuildCrcTable();

    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>
    /// Reads the icon of <paramref name="executablePath"/> and encodes it as a PNG.
    /// </summary>
    /// <param name="executablePath">
    /// Full path to a local file. May be <see langword="null"/> — callers commonly have an
    /// unresolved command line, and that is not an error worth branching on at every call site.
    /// </param>
    /// <param name="size">Requested square size in pixels; clamped to 8-256.</param>
    /// <param name="ct">Cancels the extraction, which yields <see langword="null"/>.</param>
    /// <returns>
    /// PNG bytes, or <see langword="null"/> when there is no icon to be had: a blank path, a
    /// relative path, a UNC or network path, a missing file, a cloud placeholder, an icon that is
    /// entirely transparent, a cancelled token, or any failure at all.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method does not throw — cancellation included. A caller decorating a list has no reason
    /// to wrap every icon in a try block, and a cached result would otherwise honour a cancelled
    /// token differently from a fresh one purely because it was fast.
    /// </para>
    /// <para>
    /// The returned array is a fresh copy on every call, so a caller cannot corrupt the cache for
    /// everybody else by writing into it.
    /// </para>
    /// </remarks>
    public static async Task<byte[]?> TryGetPngAsync(
        string? executablePath,
        int size = 32,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return null;
        if (ct.IsCancellationRequested) return null;

        int pixels = Math.Clamp(size, MinSize, MaxSize);

        string? path = Normalise(executablePath);
        if (path is null) return null;

        string cacheKey = $"{pixels}|{path}";
        if (Cache.TryGetValue(cacheKey, out byte[]? cached)) return Copy(cached);

        byte[]? png;

        try
        {
            // Off the calling thread: this opens a binary and talks to the shell, which is fine
            // work for a thread pool thread and completely wrong work for a UI thread.
            png = await Task.Run(() => Extract(path, pixels), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return null;
        }

        if (Cache.Count < MaxCacheEntries) Cache[cacheKey] = png;

        return Copy(png);
    }

    /// <summary>Empties the session cache. Only useful in tests.</summary>
    public static void ClearCache() => Cache.Clear();

    private static byte[]? Copy(byte[]? png) => png is null ? null : (byte[])png.Clone();

    /// <summary>
    /// Turns a raw path into a full local path, or <see langword="null"/> when it is not something
    /// we are willing to touch.
    /// </summary>
    private static string? Normalise(string path)
    {
        try
        {
            string trimmed = path.Trim().Trim('"').Trim();
            if (trimmed.Length == 0) return null;

            trimmed = Environment.ExpandEnvironmentVariables(trimmed).Trim();
            if (trimmed.Length == 0) return null;

            // A relative path would silently resolve against this process's working directory,
            // which has nothing to do with the program being described.
            if (!Path.IsPathFullyQualified(trimmed)) return null;

            // UNC shares, administrative shares and device paths all start this way.
            if (trimmed.StartsWith(@"\\", StringComparison.Ordinal)) return null;

            string full = Path.GetFullPath(trimmed);

            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root)) return null;
            if (root.StartsWith(@"\\", StringComparison.Ordinal)) return null;

            // A mapped network drive looks local until you read from it.
            DriveInfo drive = new(root);
            if (drive.DriveType is DriveType.Network or DriveType.NoRootDirectory) return null;

            return full;
        }
        catch
        {
            // Illegal characters, a path longer than the OS accepts, a drive that is not there.
            return null;
        }
    }

    /// <summary>The whole native path, wrapped so that no failure can escape.</summary>
    private static byte[]? Extract(string path, int size)
    {
        try
        {
            FileInfo file = new(path);
            if (!file.Exists) return null;

            // Reading the icon out of a dehydrated placeholder would pull the entire file down.
            if (CloudFiles.IsPlaceholder(file)) return null;

            IntPtr icon = LoadIcon(path, size);
            if (icon == IntPtr.Zero) return null;

            try
            {
                byte[]? rgba = ToRgba(icon, size);
                return rgba is null ? null : EncodePng(size, rgba);
            }
            finally
            {
                // One leaked HICON per row per rescan is a real GDI leak, and lists like this are
                // rebuilt on every scan. The handle is released on every exit path, always.
                DestroyIcon(icon);
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Asks the shell for the icon Windows itself would show for this file. That resolves
    /// shortcuts, registered file types and embedded resources in one call, and falls back to the
    /// generic executable icon for a binary that carries no icon of its own — which is what Task
    /// Manager shows too, and still more informative than a placeholder glyph.
    /// </summary>
    private static IntPtr LoadIcon(string path, int size)
    {
        SHFILEINFOW info = default;
        uint flags = ShgfiIcon | (size <= 16 ? ShgfiSmallIcon : ShgfiLargeIcon);

        IntPtr result = SHGetFileInfoW(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFOW>(), flags);

        return result == IntPtr.Zero ? IntPtr.Zero : info.hIcon;
    }

    /// <summary>
    /// Renders an <c>HICON</c> to straight-alpha RGBA, or <see langword="null"/> when it turns out
    /// to be fully transparent.
    /// </summary>
    private static byte[]? ToRgba(IntPtr icon, int size)
    {
        byte[]? onBlack = Render(icon, size, background: 0x00);
        if (onBlack is null) return null;

        bool anyAlpha = false;
        bool anyChannelAboveAlpha = false;

        for (int i = 0; i < onBlack.Length; i += 4)
        {
            byte a = onBlack[i + 3];
            if (a != 0) anyAlpha = true;
            if (onBlack[i] > a || onBlack[i + 1] > a || onBlack[i + 2] > a) anyChannelAboveAlpha = true;
        }

        if (!anyAlpha)
        {
            // A legacy icon carries a 1-bit mask instead of an alpha channel, so nothing was
            // written to the alpha byte and the image would decode as completely invisible. Draw
            // it a second time over white: the pixels whose colour moved with the background are
            // exactly the masked-out ones.
            byte[]? onWhite = Render(icon, size, background: 0xFF);
            if (onWhite is null) return null;

            for (int i = 0; i < onBlack.Length; i += 4)
            {
                bool masked = onBlack[i] != onWhite[i]
                           || onBlack[i + 1] != onWhite[i + 1]
                           || onBlack[i + 2] != onWhite[i + 2];

                onBlack[i + 3] = masked ? (byte)0x00 : (byte)0xFF;
            }
        }
        else if (!anyChannelAboveAlpha)
        {
            // No channel exceeds its own alpha anywhere, which is only true of premultiplied data
            // (or of data where the distinction cannot matter). PNG stores straight alpha, so
            // divide it back out; fully opaque and fully transparent pixels are unaffected either
            // way, so this is a no-op for the common case of a flat, opaque icon.
            for (int i = 0; i < onBlack.Length; i += 4)
            {
                int a = onBlack[i + 3];
                if (a is 0 or 0xFF) continue;

                onBlack[i] = Unpremultiply(onBlack[i], a);
                onBlack[i + 1] = Unpremultiply(onBlack[i + 1], a);
                onBlack[i + 2] = Unpremultiply(onBlack[i + 2], a);
            }
        }

        bool anyVisible = false;

        // GDI hands back BGRA; PNG wants RGBA.
        for (int i = 0; i < onBlack.Length; i += 4)
        {
            (onBlack[i], onBlack[i + 2]) = (onBlack[i + 2], onBlack[i]);
            if (onBlack[i + 3] != 0) anyVisible = true;
        }

        return anyVisible ? onBlack : null;
    }

    private static byte Unpremultiply(byte channel, int alpha) =>
        (byte)Math.Min(0xFF, channel * 0xFF / alpha);

    /// <summary>
    /// Draws <paramref name="icon"/> into a freshly allocated 32-bit DIB and returns its bytes as
    /// top-down BGRA.
    /// </summary>
    /// <param name="background">
    /// Byte the DIB is filled with before drawing. Because the DIB memory belongs to us, the
    /// background is set by writing it rather than by blitting a brush, which keeps the GDI object
    /// count at one bitmap and one DC.
    /// </param>
    private static byte[]? Render(IntPtr icon, int size, byte background)
    {
        IntPtr dc = IntPtr.Zero;
        IntPtr bitmap = IntPtr.Zero;
        IntPtr previous = IntPtr.Zero;

        try
        {
            dc = CreateCompatibleDC(IntPtr.Zero);
            if (dc == IntPtr.Zero) return null;

            BITMAPINFOHEADER header = new()
            {
                biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                biWidth = size,

                // Negative height means top-down rows, which is the order PNG wants. Getting this
                // wrong shows up as a vertically mirrored icon, not as a failure.
                biHeight = -size,
                biPlanes = 1,
                biBitCount = 32,
                biCompression = BiRgb,
            };

            bitmap = CreateDIBSection(dc, ref header, DibRgbColors, out IntPtr bits, IntPtr.Zero, 0);
            if (bitmap == IntPtr.Zero || bits == IntPtr.Zero) return null;

            int byteCount = size * size * 4;
            byte[] buffer = new byte[byteCount];

            if (background != 0x00)
            {
                Array.Fill(buffer, background);
                Marshal.Copy(buffer, 0, bits, byteCount);
            }

            previous = SelectObject(dc, bitmap);
            if (!DrawIconEx(dc, 0, 0, icon, size, size, 0, IntPtr.Zero, DiNormal)) return null;

            // GDI batches drawing per thread; without this the DIB may still be untouched.
            GdiFlush();

            Marshal.Copy(bits, buffer, 0, byteCount);
            return buffer;
        }
        finally
        {
            if (dc != IntPtr.Zero && previous != IntPtr.Zero) SelectObject(dc, previous);
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            if (dc != IntPtr.Zero) DeleteDC(dc);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Minimal PNG writer: signature, IHDR, one IDAT, IEND. No filtering and no interlacing,
    // because these images are 32x32 and the encoder's job is correctness, not compression.
    // ---------------------------------------------------------------------------------------

    private static byte[] EncodePng(int size, byte[] rgba)
    {
        using MemoryStream output = new(rgba.Length / 2 + 128);
        output.Write(PngSignature);

        Span<byte> ihdr = stackalloc byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr[..4], size);
        BinaryPrimitives.WriteInt32BigEndian(ihdr[4..8], size);
        ihdr[8] = 8;  // bits per channel
        ihdr[9] = 6;  // colour type 6: truecolour with alpha
        ihdr[10] = 0; // compression method: deflate, the only one PNG defines
        ihdr[11] = 0; // filter method: adaptive
        ihdr[12] = 0; // not interlaced

        WriteChunk(output, "IHDR", ihdr);
        WriteChunk(output, "IDAT", Compress(size, rgba));
        WriteChunk(output, "IEND", []);

        return output.ToArray();
    }

    private static byte[] Compress(int size, byte[] rgba)
    {
        int stride = size * 4;

        using MemoryStream raw = new((stride + 1) * size);

        for (int row = 0; row < size; row++)
        {
            raw.WriteByte(0); // per-scanline filter type 0: none
            raw.Write(rgba, row * stride, stride);
        }

        using MemoryStream compressed = new();

        // ZLibStream, not DeflateStream: PNG's IDAT payload is a zlib stream, header and Adler-32
        // checksum included.
        using (ZLibStream zlib = new(compressed, CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(raw.GetBuffer(), 0, (int)raw.Length);

        return compressed.ToArray();
    }

    private static void WriteChunk(Stream output, string type, ReadOnlySpan<byte> data)
    {
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteInt32BigEndian(header[..4], data.Length);
        for (int i = 0; i < 4; i++) header[4 + i] = (byte)type[i];

        // The CRC covers the type and the payload, but not the length.
        uint crc = Crc32(0u, header[4..]);
        crc = Crc32(crc, data);

        output.Write(header);
        output.Write(data);

        Span<byte> checksum = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(checksum, crc);
        output.Write(checksum);
    }

    private static uint[] BuildCrcTable()
    {
        uint[] table = new uint[256];

        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;

            table[n] = c;
        }

        return table;
    }

    /// <summary>
    /// CRC-32 as PNG defines it. Chainable: feed the previous result back in as
    /// <paramref name="running"/> to continue over a second buffer.
    /// </summary>
    private static uint Crc32(uint running, ReadOnlySpan<byte> data)
    {
        uint c = running ^ 0xFFFFFFFFu;

        foreach (byte b in data)
            c = CrcTable[(c ^ b) & 0xFF] ^ (c >> 8);

        return c ^ 0xFFFFFFFFu;
    }

    // ---------------------------------------------------------------------------------------
    // Interop. DllImport rather than LibraryImport: the source-generated variant needs
    // AllowUnsafeBlocks, which this project does not enable.
    // ---------------------------------------------------------------------------------------

    private const uint ShgfiIcon = 0x000000100;
    private const uint ShgfiSmallIcon = 0x000000001;
    private const uint ShgfiLargeIcon = 0x000000000;

    private const uint DiNormal = 0x0003; // DI_IMAGE | DI_MASK
    private const uint BiRgb = 0;
    private const uint DibRgbColors = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfoW(
        string pszPath, uint dwFileAttributes, ref SHFILEINFOW psfi, uint cbFileInfo, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern bool DrawIconEx(
        IntPtr hdc, int xLeft, int yTop, IntPtr hIcon, int cxWidth, int cyWidth,
        uint istepIfAniCur, IntPtr hbrFlickerFreeDraw, uint diFlags);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteDC(IntPtr hdc);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateDIBSection(
        IntPtr hdc, ref BITMAPINFOHEADER pbmi, uint usage,
        out IntPtr ppvBits, IntPtr hSection, uint offset);

    [DllImport("gdi32.dll")]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr ho);

    [DllImport("gdi32.dll")]
    private static extern bool GdiFlush();
}
