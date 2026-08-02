using System.Diagnostics;
using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// The counterpart to <see cref="PathSafetyTests"/> for the hand-picked deletion path.
///
/// <para>
/// <see cref="PathSafety"/> is an allowlist, so a gap in it is merely annoying. This guard is a
/// denylist standing between a single confirmation dialog and <c>SHFileOperation</c>, so a gap in it
/// is a destroyed Windows install. Every test here asserts a REFUSAL, and the handful of
/// allow-assertions exist only to prove the guard has not degenerated into refusing everything.
/// </para>
///
/// <para>
/// Nothing here deletes anything outside a temp fixture this class created. The junction tests point
/// a junction <em>at</em> real system folders on purpose — that is the attack — but only ever remove
/// the junction itself, never its target.
/// </para>
/// </summary>
public sealed class SystemPathGuardTests : IDisposable
{
    private readonly string _fixture =
        Path.Combine(Path.GetTempPath(), "cmw_guard_" + Guid.NewGuid().ToString("N")[..12]);

    private readonly List<string> _junctions = [];

    public SystemPathGuardTests() => Directory.CreateDirectory(_fixture);

    // ================================================================== catastrophic locations

    public static TheoryData<string> CatastrophicPaths()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string users = Path.GetDirectoryName(home)!;
        string drive = Path.GetPathRoot(win)!;

        return new TheoryData<string>
        {
            // Drive roots, in every spelling a root can take.
            @"C:\",
            @"C:/",
            @"C:\\",
            @"C:\.",
            @"C:\Windows\..",
            "C:",           // resolves to the *current directory* on C:, not to the root
            @"\",
            "",
            "   ",

            // Windows itself.
            win,
            Path.Combine(win, "System32"),
            Path.Combine(win, "SysWOW64"),
            Path.Combine(win, "System32", "kernel32.dll"),
            Path.Combine(win, "System32", "config", "SAM"),
            Path.Combine(win, "explorer.exe"),
            Environment.GetFolderPath(Environment.SpecialFolder.System),

            // Machine-wide program state.
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),

            // Accounts. Only the current profile can be resolved by name, so the others have to be
            // caught structurally or a user could delete a colleague's whole profile.
            home,
            users,
            Path.Combine(users, "Public"),
            Path.Combine(users, "Default"),
            Path.Combine(users, "SomeOtherAccount"),

            // The profile's own top-level folders.
            Path.Combine(home, "Desktop"),
            Path.Combine(home, "Documents"),
            Path.Combine(home, "Downloads"),
            Path.Combine(home, "Pictures"),
            Path.Combine(home, "Music"),
            Path.Combine(home, "Videos"),

            // AppData: usually the largest folder under a profile, so the most likely thing a user
            // drilling into a treemap mistakes for junk, and the loss takes every program with it.
            Path.Combine(home, "AppData"),
            Path.Combine(home, "AppData", "Local"),
            Path.Combine(home, "AppData", "LocalLow"),
            Path.Combine(home, "AppData", "Roaming"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),

            // Files Windows owns wherever they appear.
            Path.Combine(drive, "pagefile.sys"),
            Path.Combine(drive, "hiberfil.sys"),
            Path.Combine(drive, "swapfile.sys"),
            Path.Combine(drive, "bootmgr"),
            Path.Combine(drive, "bootnxt"),
            Path.Combine(drive, "bootTel.dat"),
            @"D:\pagefile.sys",

            // Boot data, and volume-level stores no user created.
            Path.Combine(drive, "Boot"),
            Path.Combine(drive, "EFI"),
            Path.Combine(drive, "Recovery"),
            Path.Combine(drive, "Boot", "BCD"),
            Path.Combine(drive, "$Recycle.Bin"),
            Path.Combine(drive, "$Recycle.Bin", "S-1-5-21-1", "$RABCDEF.txt"),
            Path.Combine(drive, "System Volume Information"),
            Path.Combine(home, "Nested", "System Volume Information", "x"),
        };
    }

    [Theory]
    [MemberData(nameof(CatastrophicPaths))]
    public void Refuses_locations_whose_loss_would_be_catastrophic(string path)
        => AssertRefused(path);

    // ================================================================== path-syntax bypasses

    /// <summary>
    /// Every entry in the guard's tables is spelled <c>X:\…</c>, so a path naming the same location
    /// in any other syntax matches none of them. <c>Path.GetFullPath</c> does not help: it leaves
    /// <c>\\?\</c> and <c>\\.\</c> prefixes alone (and stops collapsing <c>..</c> inside them) and
    /// keeps UNC paths as UNC — and <c>\\localhost\C$\Windows\System32</c> is the local System32.
    /// </summary>
    public static TheoryData<string> NonLocalSpellingsOfSystemPaths() => new()
    {
        @"\\?\C:\Windows",
        @"\\?\C:\Windows\System32",
        @"\\?\C:\Windows\System32\kernel32.dll",
        @"\\?\C:\ProgramData",
        @"\\?\C:\Windows\..\Windows\System32",
        @"\\.\C:\Windows",
        @"\\.\C:\Windows\System32",
        @"\??\C:\Windows\System32",
        @"//?/C:/Windows/System32",
        @"\\localhost\C$\Windows",
        @"\\localhost\C$\Windows\System32",
        @"\\127.0.0.1\C$\Windows\System32",
        @"\\?\UNC\localhost\C$\Windows",
        @"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows",
        @"\\.\GLOBALROOT\Device\HarddiskVolume1\Windows",
        @"\\?\Volume{11111111-2222-3333-4444-555555555555}\Windows",
        @"\\server\share\anything.txt",
        @"\\server\C$",
    };

    [Theory]
    [MemberData(nameof(NonLocalSpellingsOfSystemPaths))]
    public void Refuses_device_extended_and_UNC_spellings(string path)
        => AssertRefused(path);

    // ================================================================== normalisation tricks

    public static TheoryData<string> DisguisedSystemPaths()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string drive = Path.GetPathRoot(win)!;

        return new TheoryData<string>
        {
            // Case-only differences.
            win.ToLowerInvariant(),
            win.ToUpperInvariant(),
            Path.Combine(win, "System32").ToLowerInvariant(),

            // Forward slashes.
            Path.Combine(win, "System32").Replace('\\', '/'),

            // Trailing dots and spaces, which Windows strips when it opens the file.
            Path.Combine(win, "System32") + ".",
            Path.Combine(win, "System32") + "  ",
            Path.Combine(win, "System32") + ". . ",
            win + ".",

            // Doubled separators.
            drive + @"Windows\\System32",

            // ".." traversal, including a walk out of a harmless folder and back into Windows.
            Path.Combine(win, "System32", "..", "System32"),
            Path.Combine(win, "..", "Windows", "System32"),
            @"C:\Users\Public\..\..\Windows\System32",
            @"C:\Users\Public\..\..\Windows\..\Windows\System32\..\System32",
            EscapeFromTempIntoWindows(),

            // 8.3 short names for the long-named protected folders.
            drive + @"PROGRA~1",
            drive + @"PROGRA~2",
            drive + @"PROGRA~3",
            drive + @"PROGRA~3\Microsoft",
        };
    }

    [Theory]
    [MemberData(nameof(DisguisedSystemPaths))]
    public void Refuses_system_paths_however_they_are_spelled(string path)
        => AssertRefused(path);

    /// <summary>
    /// Climbs out of the temp folder with as many <c>..</c> segments as it takes to reach the drive
    /// root, then walks back into <c>Windows\System32</c>. The depth of the temp folder is
    /// machine-dependent, so it is counted rather than guessed.
    /// </summary>
    private static string EscapeFromTempIntoWindows()
    {
        string temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        string root = Path.GetPathRoot(temp)!;

        int depth = temp[root.Length..]
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries).Length;

        return Path.Combine([temp, .. Enumerable.Repeat("..", depth), "Windows", "System32"]);
    }

    /// <summary>
    /// <c>::$INDEX_ALLOCATION</c> is a name for the directory itself, so it slips past every
    /// exact-match rule while <c>Directory.Exists</c> happily confirms the folder is there. Applied
    /// to a folder that is protected as a whole — a profile root, Documents, the Users folder — it
    /// would turn a refusal into an approval.
    /// </summary>
    public static TheoryData<string> AlternateDataStreamSpellings()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string users = Path.GetDirectoryName(home)!;

        return new TheoryData<string>
        {
            win + "::$INDEX_ALLOCATION",
            win + ":$DATA",
            Path.Combine(win, "System32") + "::$INDEX_ALLOCATION",
            Path.Combine(win, "System32") + ":$I30:$INDEX_ALLOCATION",
            home + "::$INDEX_ALLOCATION",
            users + "::$INDEX_ALLOCATION",
            Path.Combine(home, "Documents") + "::$INDEX_ALLOCATION",
            Path.Combine(home, "AppData", "Local") + "::$INDEX_ALLOCATION",
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + "::$INDEX_ALLOCATION",
            Path.Combine(home, "Documents") + ":hidden.txt",
        };
    }

    [Theory]
    [MemberData(nameof(AlternateDataStreamSpellings))]
    public void Refuses_alternate_data_stream_spellings(string path)
        => AssertRefused(path);

    [Theory]
    [InlineData(@"C:\Users\*")]
    [InlineData(@"C:\Users\me\Documents\*")]
    [InlineData(@"C:\Users\me\Documents\*.*")]
    [InlineData(@"C:\Users\me\Documents\?otes.txt")]
    public void Refuses_wildcards_because_the_shell_expands_them(string path)
        => AssertRefused(path);

    [Theory]
    [InlineData("C:\\Users\\me\\a\0b.txt")]
    [InlineData("C:\\Users\\me\\a\rb.txt")]
    [InlineData("C:\\Users\\me\\a\nb.txt")]
    [InlineData("C:\\Users\\me\\a\tb.txt")]
    public void Refuses_paths_containing_control_characters(string path)
        => AssertRefused(path);

    // ================================================================== links and junctions

    /// <summary>
    /// The worst hole this guard can have. A junction is creatable without administrator rights, and
    /// a path <em>through</em> one carries no reparse attribute of its own — so checking only the
    /// final component leaves <c>…\link\System32</c> looking like an ordinary folder while it
    /// resolves straight onto the real one.
    /// </summary>
    [Fact]
    public void Refuses_paths_that_reach_Windows_through_a_junction()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string link = Path.Combine(_fixture, "winlink");

        if (!TryCreateJunction(link, win)) return; // junctions unavailable: nothing to assert

        AssertRefused(link);                                    // the junction itself
        AssertRefused(Path.Combine(link, "System32"));          // *through* the junction
        AssertRefused(Path.Combine(link, "System32", "kernel32.dll"));
        AssertRefused(Path.Combine(link, "explorer.exe"));
        AssertRefused(Path.Combine(link, "System32", "..", "System32"));
    }

    /// <summary>
    /// The same rule without pointing anything at Windows: any item reached through a link is
    /// refused, because the guard cannot judge where the path really lands.
    /// </summary>
    [Fact]
    public void Refuses_anything_reached_through_a_link_at_any_depth()
    {
        string real = Path.Combine(_fixture, "real", "deep", "deeper");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "payload.txt"), "x");

        string link = Path.Combine(_fixture, "hop");
        if (!TryCreateJunction(link, Path.Combine(_fixture, "real"))) return;

        AssertRefused(Path.Combine(link, "deep"));
        AssertRefused(Path.Combine(link, "deep", "deeper"));
        AssertRefused(Path.Combine(link, "deep", "deeper", "payload.txt"));
    }

    // ================================================================== positive controls

    /// <summary>
    /// A guard that refuses everything is useless — the Disk Space page exists to delete the user's
    /// own large files. These assert the guard still says yes to those.
    /// </summary>
    [Fact]
    public void Allows_the_users_own_files_and_folders()
    {
        string nested = Path.Combine(_fixture, "holiday", "2024");
        Directory.CreateDirectory(nested);

        string file = Path.Combine(nested, "video.mp4");
        File.WriteAllText(file, "not really a video");

        AssertAllowed(file);
        AssertAllowed(nested);
        AssertAllowed(Path.Combine(_fixture, "holiday"));
        AssertAllowed(_fixture);
    }

    /// <summary>
    /// AppData and the profile's main folders are refused as an <em>exact</em> match only. Losing one
    /// file out of Documents is an undo away; losing Documents is not.
    /// </summary>
    [Fact]
    public void Protects_the_main_folders_themselves_but_not_their_contents()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Names that cannot exist are used on purpose: the point is the *rule*, and a real folder
        // would drag in whatever OneDrive or a redirected known folder has done to this machine.
        AssertRefused(Path.Combine(home, "AppData", "Local"));
        AssertAllowed(Path.Combine(home, "AppData", "Local", "cmw-no-vendor", "cache", "blob.bin"));
        AssertAllowed(Path.Combine(home, "AppData", "Roaming", "cmw-no-vendor", "state.json"));
        AssertAllowed(Path.Combine(home, "cmw-no-folder", "notes", "todo.txt"));
    }

    // ================================================================== contract

    [Fact]
    public void Every_refusal_explains_itself_and_every_allowance_stays_silent()
    {
        IEnumerable<object[]> rows =
            Enumerable.Concat<object[]>(CatastrophicPaths(), NonLocalSpellingsOfSystemPaths());

        foreach (object[] row in rows)
        {
            string path = (string)row[0];
            Assert.True(SystemPathGuard.IsProtected(path, out string? reason));
            Assert.False(string.IsNullOrWhiteSpace(reason), $"No reason given for '{path}'");
        }

        Assert.False(SystemPathGuard.IsProtected(_fixture, out string? none));
        Assert.Null(none);
    }

    [Theory]
    [InlineData("::::")]
    [InlineData(@"C:\|pipe")]
    [InlineData("C:\\Users\\\"quote\"")]
    [InlineData(@"nul")]
    [InlineData(@"CON")]
    [InlineData(@"C:\Users\me\a<b>c")]
    public void Never_throws_on_hostile_input_and_defaults_to_refusing(string path)
    {
        bool protectedPath = SystemPathGuard.IsProtected(path, out string? reason);

        // The value matters less than the absence of an exception, but a path the guard could not
        // even parse must never come back as "safe to delete".
        Assert.True(protectedPath, $"Unparseable input '{path}' was reported as deletable");
        Assert.False(string.IsNullOrWhiteSpace(reason));
    }

    [Fact]
    public void Flags_installed_programs_as_risky_without_blocking_them()
    {
        string programs = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string inside = Path.Combine(programs, "SomeVendor", "SomeApp", "data.bin");

        Assert.True(SystemPathGuard.IsRisky(inside, out string? warning));
        Assert.False(string.IsNullOrWhiteSpace(warning));

        Assert.False(SystemPathGuard.IsRisky(Path.Combine(_fixture, "video.mp4"), out string? quiet));
        Assert.Null(quiet);
    }

    /// <summary>
    /// <see cref="SystemPathGuard.IsRisky"/> is called on every treemap selection, including ones the
    /// user is only hovering past, so it has to survive anything without throwing.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("::::")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"C:\|pipe")]
    [InlineData(@"\\server\share")]
    [InlineData("C:\\a\0b")]
    public void IsRisky_never_throws_and_never_warns_about_a_path_it_cannot_read(string path)
    {
        Assert.False(SystemPathGuard.IsRisky(path, out string? warning));
        Assert.Null(warning);
    }

    // ================================================================== helpers

    private static void AssertRefused(string path)
    {
        bool refused = SystemPathGuard.IsProtected(path, out string? reason);
        Assert.True(refused, $"SystemPathGuard allowed deletion of '{path}'");
        Assert.False(string.IsNullOrWhiteSpace(reason), $"No reason given for '{path}'");
    }

    private static void AssertAllowed(string path)
    {
        bool refused = SystemPathGuard.IsProtected(path, out string? reason);
        Assert.False(refused, $"SystemPathGuard refused the user's own '{path}': {reason}");
    }

    /// <summary>
    /// Creates a directory junction, recording it so <see cref="Dispose"/> can remove the link
    /// without ever touching what it points at. Returns false when junctions are unavailable, which
    /// leaves the calling test with nothing to prove rather than failing for the wrong reason.
    /// </summary>
    private bool TryCreateJunction(string link, string target)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(
                "cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null) return false;

            process.WaitForExit(15_000);
        }
        catch (Exception)
        {
            return false;
        }

        if (!Directory.Exists(link)) return false;

        _junctions.Add(link);
        return true;
    }

    public void Dispose()
    {
        // Junctions first and individually: Directory.Delete removes the link, never its target,
        // and doing this before the recursive sweep means no recursion can ever run through one.
        foreach (string junction in _junctions)
        {
            try { Directory.Delete(junction); }
            catch (Exception) { /* nothing left to do in a test teardown */ }
        }

        try
        {
            if (!Directory.Exists(_fixture)) return;

            // Refuse to sweep recursively while any reparse point remains inside the fixture.
            foreach (string dir in Directory.EnumerateDirectories(_fixture, "*", SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0) return;
            }

            Directory.Delete(_fixture, recursive: true);
        }
        catch (Exception)
        {
            // A leftover temp folder is a smaller problem than a throwing teardown.
        }
    }
}
