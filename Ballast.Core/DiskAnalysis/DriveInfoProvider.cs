using Ballast.Core.Util;

namespace Ballast.Core.DiskAnalysis;

/// <summary>
/// Capacity snapshot for one fixed drive. Read-only; taken at a point in time.
/// </summary>
/// <param name="Name">Drive name as Windows reports it, e.g. <c>C:\</c>.</param>
/// <param name="RootPath">Root directory to hand to <see cref="DirectoryTreeScanner"/>.</param>
/// <param name="Label">Volume label, or <see langword="null"/> when unset or unreadable.</param>
/// <param name="TotalBytes">Total formatted capacity.</param>
/// <param name="FreeBytes">
/// Space available to the current user. This is the quota-aware figure Explorer shows, so on a
/// quota-limited volume it can be smaller than the raw free space.
/// </param>
/// <param name="FileSystem">Reported filesystem (<c>NTFS</c>, <c>FAT32</c>, ...), or null if unreadable.</param>
public sealed record DriveSummary(
    string Name,
    string RootPath,
    string? Label,
    long TotalBytes,
    long FreeBytes,
    string? FileSystem = null)
{
    /// <summary>
    /// True when this volume looks like a cloud sync mount (Google Drive for desktop, and similar
    /// tools that expose an account as a lettered "fixed" disk) rather than a real local disk.
    ///
    /// <para>
    /// Windows reports these as <see cref="DriveType.Fixed"/>, so type alone cannot tell them
    /// apart. Two signals do, and both must hold to avoid false positives on genuine removable
    /// media that happens to be FAT-formatted:
    /// </para>
    /// <list type="bullet">
    /// <item>A volume label containing <c>@</c> — the account e-mail these clients use as the label.</item>
    /// <item>A <c>FAT32</c> volume larger than 32 GB. Windows refuses to format FAT32 above that,
    /// so a 250 GB "FAT32 fixed disk" is a synthetic mount, not real media. exFAT is deliberately
    /// excluded here: large exFAT external drives are perfectly normal.</item>
    /// </list>
    ///
    /// <para>
    /// It matters because the reported capacity is the account quota, not local disk: "94% full"
    /// is meaningless, freeing space there does nothing for the real disk, and walking it is slow.
    /// </para>
    /// </summary>
    public bool IsLikelyCloudMount =>
        (Label?.Contains('@') ?? false) ||
        (string.Equals(FileSystem, "FAT32", StringComparison.OrdinalIgnoreCase) &&
         TotalBytes > 32L * 1024 * 1024 * 1024);

    /// <summary>Occupied bytes; clamped at 0 so a stale snapshot can never go negative.</summary>
    public long UsedBytes => Math.Max(0, TotalBytes - FreeBytes);

    /// <summary>Occupied share in the range 0..1. Returns 0 when capacity is unknown.</summary>
    public double UsedFraction =>
        TotalBytes > 0 ? Math.Clamp((double)UsedBytes / TotalBytes, 0d, 1d) : 0d;

    /// <summary>Label-first title for the UI, e.g. <c>Windows (C:)</c>.</summary>
    public string DisplayName =>
        string.IsNullOrWhiteSpace(Label)
            ? Name
            : $"{Label} ({Name.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)})";

    public string UsedDisplay => ByteFormatter.Format(UsedBytes);
    public string FreeDisplay => ByteFormatter.Format(FreeBytes);
    public string TotalDisplay => ByteFormatter.Format(TotalBytes);
}

/// <summary>
/// Lists the local fixed disks worth analysing. Removable, network and optical volumes are
/// excluded: they are slow to walk and rarely what the user means by "my disk".
/// </summary>
/// <remarks>
/// Every drive is probed inside its own try/catch — one unhealthy volume (BitLocker locked,
/// a failing disk, a drive pulled mid-enumeration) must not cost the user the whole list.
/// </remarks>
public sealed class DriveInfoProvider
{
    /// <summary>Shared instance for callers that are not using dependency injection. Stateless and thread-safe.</summary>
    public static DriveInfoProvider Shared { get; } = new();

    /// <summary>
    /// Fixed, ready drives ordered by name. Returns an empty list rather than throwing when the
    /// drive table itself cannot be read.
    /// </summary>
    public IReadOnlyList<DriveSummary> GetFixedDrives()
    {
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        var summaries = new List<DriveSummary>(drives.Length);

        foreach (var drive in drives)
        {
            if (Describe(drive) is { } summary)
                summaries.Add(summary);
        }

        summaries.Sort(static (a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return summaries;
    }

    /// <summary>
    /// Reads one drive. Returns <see langword="null"/> when the drive is not a ready fixed disk
    /// or when any of its properties throws — <c>IsReady</c> is a race, not a guarantee.
    /// </summary>
    private static DriveSummary? Describe(DriveInfo drive)
    {
        try
        {
            if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                return null;

            string? label = null;
            try
            {
                label = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? null : drive.VolumeLabel;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Label is cosmetic; a drive with an unreadable label is still worth listing.
            }

            string? fileSystem = null;
            try
            {
                fileSystem = string.IsNullOrWhiteSpace(drive.DriveFormat) ? null : drive.DriveFormat;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Only used to spot synthetic cloud mounts; absence is not fatal.
            }

            long total = drive.TotalSize;
            long free = Math.Clamp(drive.AvailableFreeSpace, 0, total > 0 ? total : long.MaxValue);

            return new DriveSummary(
                drive.Name, drive.RootDirectory.FullName, label, total, free, fileSystem);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }
}
