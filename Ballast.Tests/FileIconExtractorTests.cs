using System.Buffers.Binary;
using System.IO.Compression;
using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Covers <see cref="FileIconExtractor"/> against files every Windows install has, so nothing here
/// depends on a particular program being present. <c>explorer.exe</c> lives directly under
/// <c>%WINDIR%</c> on every supported version and carries a modern 32-bit icon;
/// <c>System32\shell32.dll</c> is the other guaranteed icon source.
/// </summary>
public class FileIconExtractorTests
{
    private static string WindowsDirectory => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static string Explorer => Path.Combine(WindowsDirectory, "explorer.exe");

    // ---------------------------------------------------------------------------------------
    // Refusals. Every one of these must be a null, never an exception: the caller treats an
    // icon as decoration and does not guard the call.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public async Task BlankPathReturnsNull(string? path)
    {
        Assert.Null(await FileIconExtractor.TryGetPngAsync(path));
    }

    [Fact]
    public async Task MissingFileReturnsNull()
    {
        string missing = Path.Combine(Path.GetTempPath(), $"ballast-no-such-{Guid.NewGuid():N}.exe");

        Assert.Null(await FileIconExtractor.TryGetPngAsync(missing));
    }

    [Fact]
    public async Task DirectoryThatIsNotAFileReturnsNull()
    {
        Assert.Null(await FileIconExtractor.TryGetPngAsync(WindowsDirectory));
    }

    [Fact]
    public async Task RelativePathReturnsNull()
    {
        // Resolving this against the process working directory would describe some other file.
        Assert.Null(await FileIconExtractor.TryGetPngAsync("explorer.exe"));
    }

    [Theory]
    [InlineData(@"\\some-server\share\app.exe")]
    [InlineData(@"\\?\C:\Windows\explorer.exe")]
    [InlineData(@"\\.\PIPE\anything")]
    public async Task UncAndDevicePathsReturnNull(string path)
    {
        Assert.Null(await FileIconExtractor.TryGetPngAsync(path));
    }

    [Theory]
    [InlineData("C:\\Windows\\|<>.exe")]
    [InlineData("%NO_SUCH_VARIABLE_BALLAST%\\app.exe")]
    public async Task MalformedPathReturnsNull(string path)
    {
        Assert.Null(await FileIconExtractor.TryGetPngAsync(path));
    }

    /// <summary>
    /// Cancellation yields null rather than an exception, and it does so whether or not the answer
    /// was already cached — a cache hit honouring a cancelled token differently from a fresh read
    /// would make this method's behaviour depend on how fast it happened to be.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationYieldsNullEvenWhenTheAnswerIsCached(bool warmTheCache)
    {
        if (warmTheCache) Assert.NotNull(await FileIconExtractor.TryGetPngAsync(Explorer, 32));

        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        Assert.Null(await FileIconExtractor.TryGetPngAsync(Explorer, 32, cts.Token));
    }

    // ---------------------------------------------------------------------------------------
    // The happy path.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task ExtractsAnIconFromExplorer()
    {
        byte[]? png = await FileIconExtractor.TryGetPngAsync(Explorer);

        Assert.NotNull(png);
        Assert.NotEmpty(png);
    }

    [Fact]
    public async Task ExtractsAnIconFromAResourceOnlyDll()
    {
        string shell32 = Path.Combine(WindowsDirectory, "System32", "shell32.dll");

        Assert.NotNull(await FileIconExtractor.TryGetPngAsync(shell32));
    }

    [Fact]
    public async Task PathIsAcceptedRegardlessOfCaseAndSurroundingQuotes()
    {
        byte[]? quoted = await FileIconExtractor.TryGetPngAsync($"\"{Explorer.ToUpperInvariant()}\"");

        Assert.NotNull(quoted);
    }

    [Fact]
    public async Task EnvironmentVariablesAreExpanded()
    {
        Assert.NotNull(await FileIconExtractor.TryGetPngAsync(@"%WINDIR%\explorer.exe"));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(48)]
    public async Task ResultIsAValidPngOfTheRequestedSize(int size)
    {
        byte[]? png = await FileIconExtractor.TryGetPngAsync(Explorer, size);

        Assert.NotNull(png);

        PngImage image = PngImage.Parse(png);

        Assert.Equal(size, image.Width);
        Assert.Equal(size, image.Height);
        Assert.Equal(8, image.BitDepth);
        Assert.Equal(6, image.ColourType);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(4096)]
    public async Task RequestedSizeIsClampedRatherThanRefused(int size)
    {
        byte[]? png = await FileIconExtractor.TryGetPngAsync(Explorer, size);

        Assert.NotNull(png);

        PngImage image = PngImage.Parse(png);

        Assert.InRange(image.Width, 8, 256);
        Assert.Equal(image.Width, image.Height);
    }

    [Fact]
    public async Task PixelsCarryRealColourAndRealTransparency()
    {
        byte[]? png = await FileIconExtractor.TryGetPngAsync(Explorer, 32);

        Assert.NotNull(png);

        PngImage image = PngImage.Parse(png);
        byte[] pixels = image.Pixels;

        bool anyOpaque = false;
        bool anyColour = false;

        for (int i = 0; i < pixels.Length; i += 4)
        {
            byte a = pixels[i + 3];
            if (a == 0xFF) anyOpaque = true;
            if (a != 0 && (pixels[i] != 0 || pixels[i + 1] != 0 || pixels[i + 2] != 0)) anyColour = true;
        }

        // A fully transparent or entirely black result is the classic symptom of mishandled icon
        // alpha, and it would render as an invisible or solid square rather than a logo.
        Assert.True(anyOpaque, "the icon has no fully opaque pixel");
        Assert.True(anyColour, "the icon is entirely black");
    }

    [Fact]
    public async Task StraightAlphaIsPreservedSoEdgesAreNotDarkened()
    {
        byte[]? png = await FileIconExtractor.TryGetPngAsync(Explorer, 32);

        Assert.NotNull(png);

        byte[] pixels = PngImage.Parse(png).Pixels;

        // Premultiplied data can never have a channel brighter than its own alpha. Finding one
        // proves the alpha was written straight, which is what the PNG format specifies.
        bool anyChannelAboveAlpha = false;

        for (int i = 0; i < pixels.Length && !anyChannelAboveAlpha; i += 4)
        {
            byte a = pixels[i + 3];
            if (a is 0 or 0xFF) continue;

            anyChannelAboveAlpha = pixels[i] > a || pixels[i + 1] > a || pixels[i + 2] > a;
        }

        Assert.True(anyChannelAboveAlpha, "no semi-transparent pixel carries straight alpha");
    }

    // ---------------------------------------------------------------------------------------
    // Caching.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task RepeatedCallsAgreeButDoNotShareTheirBuffer()
    {
        byte[]? first = await FileIconExtractor.TryGetPngAsync(Explorer, 32);
        byte[]? second = await FileIconExtractor.TryGetPngAsync(Explorer, 32);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(first, second);

        // Handing out the cached array itself would let one caller corrupt every later one.
        Assert.NotSame(first, second);

        first[0] = 0;

        byte[]? third = await FileIconExtractor.TryGetPngAsync(Explorer, 32);

        Assert.NotNull(third);
        Assert.Equal(second, third);
    }

    [Fact]
    public async Task DifferentSizesAreCachedSeparately()
    {
        byte[]? small = await FileIconExtractor.TryGetPngAsync(Explorer, 16);
        byte[]? large = await FileIconExtractor.TryGetPngAsync(Explorer, 48);

        Assert.NotNull(small);
        Assert.NotNull(large);
        Assert.Equal(16, PngImage.Parse(small).Width);
        Assert.Equal(48, PngImage.Parse(large).Width);
    }

    [Fact]
    public async Task ManyConcurrentCallsForTheSameFileAllSucceed()
    {
        FileIconExtractor.ClearCache();

        Task<byte[]?>[] calls = [.. Enumerable.Range(0, 32)
            .Select(_ => FileIconExtractor.TryGetPngAsync(Explorer, 32))];

        byte[]?[] results = await Task.WhenAll(calls);

        Assert.All(results, png => Assert.NotNull(png));
        Assert.All(results, png => Assert.Equal(results[0], png));
    }

    /// <summary>
    /// A deliberately strict PNG reader: it verifies every chunk CRC and reverses the filtering,
    /// so a subtly malformed file fails here rather than silently rendering as nothing.
    /// </summary>
    private sealed class PngImage
    {
        private static readonly uint[] CrcTable = BuildCrcTable();

        private PngImage(int width, int height, byte bitDepth, byte colourType, byte[] pixels)
        {
            Width = width;
            Height = height;
            BitDepth = bitDepth;
            ColourType = colourType;
            Pixels = pixels;
        }

        public int Width { get; }

        public int Height { get; }

        public byte BitDepth { get; }

        public byte ColourType { get; }

        /// <summary>Unfiltered, top-down RGBA.</summary>
        public byte[] Pixels { get; }

        public static PngImage Parse(byte[] png)
        {
            byte[] signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            Assert.True(png.Length > signature.Length, "file is too short to be a PNG");
            Assert.Equal(signature, png[..signature.Length]);

            int offset = signature.Length;
            int width = 0;
            int height = 0;
            byte bitDepth = 0;
            byte colourType = 0;
            bool sawEnd = false;

            using MemoryStream idat = new();

            while (offset < png.Length)
            {
                int length = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(offset, 4));
                Assert.InRange(length, 0, png.Length);

                string type = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
                ReadOnlySpan<byte> body = png.AsSpan(offset + 8, length);

                uint expected = BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(offset + 8 + length, 4));
                uint actual = Crc32(png.AsSpan(offset + 4, 4 + length));
                Assert.Equal(expected, actual);

                switch (type)
                {
                    case "IHDR":
                        Assert.Equal(13, length);
                        width = BinaryPrimitives.ReadInt32BigEndian(body[..4]);
                        height = BinaryPrimitives.ReadInt32BigEndian(body[4..8]);
                        bitDepth = body[8];
                        colourType = body[9];
                        Assert.Equal(0, body[10]);
                        Assert.Equal(0, body[11]);
                        Assert.Equal(0, body[12]);
                        break;

                    case "IDAT":
                        idat.Write(body);
                        break;

                    case "IEND":
                        Assert.Equal(0, length);
                        sawEnd = true;
                        break;
                }

                offset += 12 + length;
            }

            Assert.Equal(png.Length, offset);
            Assert.True(sawEnd, "the PNG has no IEND chunk");
            Assert.True(width > 0 && height > 0, "the PNG has no IHDR chunk");

            idat.Position = 0;

            using ZLibStream inflate = new(idat, CompressionMode.Decompress);
            using MemoryStream raw = new();
            inflate.CopyTo(raw);

            int stride = width * 4;
            byte[] scanlines = raw.ToArray();
            Assert.Equal((stride + 1) * height, scanlines.Length);

            byte[] pixels = new byte[stride * height];

            for (int row = 0; row < height; row++)
            {
                // Only filter type 0 is produced, so unfiltering is a straight copy. Asserting it
                // keeps this reader honest rather than accidentally tolerant.
                Assert.Equal(0, scanlines[row * (stride + 1)]);
                Array.Copy(scanlines, (row * (stride + 1)) + 1, pixels, row * stride, stride);
            }

            return new PngImage(width, height, bitDepth, colourType, pixels);
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

        private static uint Crc32(ReadOnlySpan<byte> data)
        {
            uint c = 0xFFFFFFFFu;

            foreach (byte b in data)
                c = CrcTable[(c ^ b) & 0xFF] ^ (c >> 8);

            return c ^ 0xFFFFFFFFu;
        }
    }
}
