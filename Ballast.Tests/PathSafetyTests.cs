using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// These are the most important tests in the solution. Every one of them asserts that the app
/// REFUSES to delete something. If any of these ever go red, the app is capable of destroying
/// user data and must not ship.
/// </summary>
public class PathSafetyTests
{
    public static TheoryData<string> ProtectedPaths()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        return new TheoryData<string>
        {
            @"C:\",
            @"D:\",
            win,
            Path.Combine(win, "System32"),
            Path.Combine(win, "System32", "kernel32.dll"),
            Path.Combine(win, "explorer.exe"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            home,
            Path.Combine(home, "Documents"),
            Path.Combine(home, "Documents", "taxes.xlsx"),
            Path.Combine(home, "Desktop", "project", "src", "Program.cs"),
            Path.Combine(home, "Pictures", "wedding.jpg"),
            Path.Combine(home, "AppData", "Roaming", "SomeApp", "settings.json"),
            "",
            "   ",
        };
    }

    [Theory]
    [MemberData(nameof(ProtectedPaths))]
    public void Refuses_to_delete_protected_locations(string path)
        => Assert.False(PathSafety.IsDeletable(path), $"PathSafety allowed deletion of '{path}'");

    [Fact]
    public void Refuses_the_temp_root_itself_but_allows_its_contents()
    {
        var temp = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);

        Assert.False(PathSafety.IsDeletable(temp));
        Assert.True(PathSafety.IsDeletable(Path.Combine(temp, "leftover.tmp")));
        Assert.True(PathSafety.IsDeletable(Path.Combine(temp, "nested", "deep", "file.bin")));
    }

    [Theory]
    [InlineData("Login Data")]
    [InlineData("Cookies")]
    [InlineData("History")]
    [InlineData("Bookmarks")]
    [InlineData("Web Data")]
    [InlineData("Local State")]
    [InlineData("logins.json")]
    [InlineData("key4.db")]
    [InlineData("places.sqlite")]
    public void Refuses_browser_credential_and_history_stores(string sensitiveFile)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = Path.Combine(local, "Google", "Chrome", "User Data", "Default");

        Assert.False(
            PathSafety.IsDeletable(Path.Combine(profile, sensitiveFile)),
            $"PathSafety allowed deletion of the '{sensitiveFile}' store");
    }

    [Fact]
    public void Still_allows_the_browser_cache_itself()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = Path.Combine(local, "Google", "Chrome", "User Data", "Default");

        Assert.True(PathSafety.IsDeletable(Path.Combine(profile, "Cache", "data_1")));
        Assert.True(PathSafety.IsDeletable(Path.Combine(profile, "Code Cache", "js", "index")));
    }

    [Fact]
    public void Escaping_with_dot_dot_does_not_bypass_the_guard()
    {
        var temp = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);
        var escape = Path.Combine(temp, "..", "..", "..", "Windows", "System32");

        Assert.False(PathSafety.IsDeletable(escape));
    }

    [Fact]
    public void EnsureDeletable_throws_for_a_protected_path()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.Throws<InvalidOperationException>(
            () => PathSafety.EnsureDeletable(Path.Combine(home, "Documents", "important.docx")));
    }
}
