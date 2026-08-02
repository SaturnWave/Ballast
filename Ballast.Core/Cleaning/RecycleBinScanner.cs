using System.Runtime.InteropServices;
using Ballast.Core.Abstractions;
using Ballast.Core.Models;

namespace Ballast.Core.Cleaning;

/// <summary>
/// The Recycle Bin is not a normal folder — it is queried and emptied through the shell,
/// so it is reported as a single <see cref="CleanupItem"/> with
/// <see cref="CleanupItem.IsVirtual"/> set. <c>CleaningService</c> routes virtual items to
/// <see cref="Empty"/> instead of a file delete.
/// </summary>
public sealed partial class RecycleBinScanner : IScanner
{
    /// <summary>Sentinel path used to identify the Recycle Bin item.</summary>
    public const string VirtualPath = "shell:RecycleBinFolder";

    public string Name => "Recycle Bin";

    public Task<ScanResult> ScanAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() =>
        {
            var (size, count) = Query();
            if (size <= 0 || count <= 0) return new ScanResult();

            var item = new CleanupItem
            {
                Path = VirtualPath,
                Category = JunkCategory.RecycleBin,
                SizeBytes = size,
                IsDirectory = true,
                IsVirtual = true,
                Description = count == 1 ? "1 item" : $"{count:N0} items",
            };

            progress?.Report(new ScanProgress("Recycle Bin", 1, size));
            return new ScanResult { Items = [item] };
        }, ct);

    /// <summary>Total size and item count across every drive's Recycle Bin.</summary>
    public static (long Size, long Count) Query()
    {
        try
        {
            var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };

            // A null root path aggregates every drive.
            int hr = SHQueryRecycleBin(null, ref info);
            return hr == 0 ? (info.i64Size, info.i64NumItems) : (0, 0);
        }
        catch (DllNotFoundException)
        {
            return (0, 0);
        }
        catch (EntryPointNotFoundException)
        {
            return (0, 0);
        }
    }

    /// <summary>Empties every Recycle Bin without showing shell confirmation UI.</summary>
    public static void Empty()
    {
        const uint SHERB_NOCONFIRMATION = 0x00000001;
        const uint SHERB_NOPROGRESSUI = 0x00000002;
        const uint SHERB_NOSOUND = 0x00000004;

        int hr = SHEmptyRecycleBin(
            IntPtr.Zero, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

        // E_UNEXPECTED (0x8000FFFF) is returned when the bin is already empty; not an error.
        if (hr != 0 && hr != unchecked((int)0x8000FFFF))
            Marshal.ThrowExceptionForHR(hr);
    }

    /// <remarks>
    /// Natural (unpacked) alignment deliberately matches the Win32 header: on x64 the DWORD
    /// is followed by 4 bytes of padding before the two 64-bit fields.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO
    {
        public int cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    // DllImport rather than LibraryImport: the source-generated variant requires
    // AllowUnsafeBlocks for the whole assembly, which is not worth it for two calls.
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
}
