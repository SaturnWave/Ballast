using Ballast.Core.Cleaning;
using Ballast.Core.Models;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Exercises real deletion, but only ever inside a throwaway folder created under %TEMP%
/// (which is an allowed cleanup root). No test here touches anything else.
/// </summary>
public sealed class CleaningServiceTests : IDisposable
{
    private readonly string _sandbox;

    public CleaningServiceTests()
    {
        _sandbox = Path.Combine(Path.GetTempPath(), "BallastTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_sandbox);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_sandbox)) Directory.Delete(_sandbox, recursive: true); }
        catch { /* best effort */ }
    }

    private string WriteFile(string relativePath, int bytes)
    {
        var full = Path.Combine(_sandbox, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, new byte[bytes]);
        return full;
    }

    [Fact]
    public async Task Deletes_a_single_file_and_reports_its_size()
    {
        var file = WriteFile("junk.tmp", 4096);

        var report = await new CleaningService().DeleteAsync(
        [
            new CleanupItem { Path = file, Category = JunkCategory.UserTemp, SizeBytes = 4096 },
        ]);

        Assert.False(File.Exists(file));
        Assert.Equal(4096, report.BytesFreed);
        Assert.Equal(1, report.ItemsDeleted);
        Assert.Empty(report.Failures);
    }

    [Fact]
    public async Task Deletes_a_directory_tree_and_sums_only_what_it_removed()
    {
        WriteFile(Path.Combine("cache", "a.bin"), 1000);
        WriteFile(Path.Combine("cache", "nested", "b.bin"), 2000);
        WriteFile(Path.Combine("cache", "nested", "deeper", "c.bin"), 3000);

        var dir = Path.Combine(_sandbox, "cache");

        var report = await new CleaningService().DeleteAsync(
        [
            new CleanupItem
            {
                Path = dir,
                Category = JunkCategory.BrowserCache,
                SizeBytes = 6000,
                IsDirectory = true,
            },
        ]);

        Assert.Equal(6000, report.BytesFreed);
        Assert.False(Directory.Exists(dir));
    }

    [Fact]
    public async Task Refuses_a_path_outside_the_allowed_roots_and_leaves_the_file_alone()
    {
        // A real file in a location the app must never touch.
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var victim = Path.Combine(docs, $"Ballast-must-not-delete-{Guid.NewGuid():N}.txt");
        File.WriteAllText(victim, "precious");

        try
        {
            var report = await new CleaningService().DeleteAsync(
            [
                new CleanupItem { Path = victim, Category = JunkCategory.UserTemp, SizeBytes = 8 },
            ]);

            Assert.True(File.Exists(victim), "CleaningService deleted a file outside the allowed roots!");
            Assert.Equal(0, report.BytesFreed);
            Assert.Equal(0, report.ItemsDeleted);
            Assert.Single(report.Failures);
        }
        finally
        {
            File.Delete(victim);
        }
    }

    [Fact]
    public async Task Skips_a_locked_file_but_still_deletes_its_siblings()
    {
        var locked = WriteFile(Path.Combine("mixed", "locked.bin"), 500);
        var free = WriteFile(Path.Combine("mixed", "free.bin"), 700);

        // Hold an exclusive handle so the delete of this one file must fail.
        using (var hold = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var report = await new CleaningService().DeleteAsync(
            [
                new CleanupItem
                {
                    Path = Path.Combine(_sandbox, "mixed"),
                    Category = JunkCategory.UserTemp,
                    SizeBytes = 1200,
                    IsDirectory = true,
                },
            ]);

            Assert.False(File.Exists(free), "the unlocked sibling should still have been removed");
            Assert.True(File.Exists(locked), "the locked file should have survived");
            Assert.Equal(700, report.BytesFreed);
            Assert.NotEmpty(report.Failures);
        }
    }

    [Fact]
    public async Task Reports_admin_requirement_rather_than_throwing()
    {
        var file = WriteFile("needs-admin.tmp", 100);

        var report = await new CleaningService().DeleteAsync(
        [
            new CleanupItem
            {
                Path = file,
                Category = JunkCategory.WindowsTemp,
                SizeBytes = 100,
                RequiresAdmin = true,
            },
        ]);

        if (Ballast.Core.Util.Elevation.IsElevated)
        {
            Assert.Equal(100, report.BytesFreed);
        }
        else
        {
            Assert.Equal(0, report.BytesFreed);
            Assert.Single(report.Failures);
            Assert.Contains("administrator", report.Failures[0].Reason, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task An_empty_selection_is_a_no_op()
    {
        var report = await new CleaningService().DeleteAsync([]);

        Assert.Equal(0, report.BytesFreed);
        Assert.Equal(0, report.ItemsDeleted);
        Assert.Empty(report.Failures);
    }
}
