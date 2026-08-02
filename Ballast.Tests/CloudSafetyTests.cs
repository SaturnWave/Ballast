using Ballast.Core.DiskAnalysis;
using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Cloud sync clients (OneDrive Files On-Demand, Google Drive for desktop) create two hazards:
/// placeholder files whose logical size is not real local usage, and lettered drives that look
/// like fixed disks but are account quotas. Both are covered here.
/// </summary>
public class CloudSafetyTests
{
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

    [Theory]
    [InlineData(FileAttributes.Offline)]
    [InlineData(RecallOnOpen)]
    [InlineData(RecallOnDataAccess)]
    [InlineData(FileAttributes.ReparsePoint)]
    [InlineData(FileAttributes.Normal | RecallOnDataAccess)]
    [InlineData(FileAttributes.Archive | FileAttributes.Offline)]
    public void Placeholder_attributes_are_recognised(FileAttributes attributes)
        => Assert.True(CloudFiles.IsPlaceholder(attributes));

    [Theory]
    [InlineData(FileAttributes.Normal)]
    [InlineData(FileAttributes.Archive)]
    [InlineData(FileAttributes.ReadOnly)]
    [InlineData(FileAttributes.Hidden | FileAttributes.System)]
    [InlineData(FileAttributes.Directory)]
    public void Ordinary_local_files_are_not_placeholders(FileAttributes attributes)
        => Assert.False(CloudFiles.IsPlaceholder(attributes));

    [Fact]
    public void Shallow_enumeration_skips_placeholders_and_stays_in_the_current_folder()
    {
        var options = CloudFiles.ShallowEnumeration();

        Assert.True(options.IgnoreInaccessible);
        Assert.False(options.RecurseSubdirectories);
        Assert.Equal(CloudFiles.PlaceholderAttributes, options.AttributesToSkip);
    }

    [Fact]
    public void A_real_local_file_is_never_treated_as_a_placeholder()
    {
        var path = Path.Combine(Path.GetTempPath(), $"Ballast-local-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, new byte[64]);

        try
        {
            Assert.False(CloudFiles.IsPlaceholder(new FileInfo(path)));
        }
        finally
        {
            File.Delete(path);
        }
    }

    // ---- Cloud drive detection ----

    private static DriveSummary Drive(string name, string? label, long total, string? fs) =>
        new(name, name, label, total, total / 2, fs);

    [Fact]
    public void An_account_labelled_volume_is_flagged_as_a_cloud_mount()
    {
        // Google Drive for desktop labels the volume with the signed-in account.
        var g = Drive(@"G:\", "someone@gmail.com - Google Drive", 254_561_742_848, "FAT32");
        Assert.True(g.IsLikelyCloudMount);
    }

    [Fact]
    public void A_large_FAT32_volume_is_flagged_even_without_a_telltale_label()
    {
        // Windows will not format FAT32 above 32 GB, so a 250 GB FAT32 "fixed disk" is synthetic.
        var d = Drive(@"X:\", "Backup", 254_561_742_848, "FAT32");
        Assert.True(d.IsLikelyCloudMount);
    }

    [Fact]
    public void Real_local_disks_are_not_flagged()
    {
        Assert.False(Drive(@"C:\", "Local Disk", 254_561_742_848, "NTFS").IsLikelyCloudMount);
        Assert.False(Drive(@"D:\", "Data", 4_000_000_000_000, "NTFS").IsLikelyCloudMount);
    }

    [Fact]
    public void Genuine_removable_media_is_not_flagged()
    {
        // A 16 GB FAT32 stick is entirely normal and must not trip the heuristic.
        Assert.False(Drive(@"E:\", "USB STICK", 16L * 1024 * 1024 * 1024, "FAT32").IsLikelyCloudMount);

        // Large exFAT external drives are normal too, so exFAT is deliberately excluded.
        Assert.False(Drive(@"F:\", "Portable", 4_000_000_000_000, "exFAT").IsLikelyCloudMount);
    }

    [Fact]
    public void Unknown_filesystem_and_missing_label_do_not_throw_or_false_positive()
    {
        Assert.False(Drive(@"Z:\", null, 100_000_000_000, null).IsLikelyCloudMount);
    }

    [Fact]
    public void This_machines_real_drives_are_classified_sensibly()
    {
        var drives = DriveInfoProvider.Shared.GetFixedDrives();

        // Whatever the machine looks like, the system drive must never be mistaken for a mount.
        var systemRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        var system = drives.FirstOrDefault(d =>
            string.Equals(d.RootPath, systemRoot, StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(system);
        Assert.False(system!.IsLikelyCloudMount, "the Windows drive was flagged as a cloud mount");
    }
}
