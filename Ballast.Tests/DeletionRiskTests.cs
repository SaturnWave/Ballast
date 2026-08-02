using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Tests for the five-step risk ramp the Disk Space view colours and filters by.
///
/// <para>
/// The assessor gives <em>advice</em> — <see cref="SystemPathGuard"/> is what actually refuses a
/// deletion — so a wrong answer here does not by itself destroy anything. It does something almost
/// as bad: it tells a person a file is safe to delete. So the assertions that matter most are the
/// ones proving nothing dangerous is ever painted green, and they are written as ceilings
/// ("never safer than X") rather than exact levels wherever the exact level is not the point.
/// </para>
///
/// <para>
/// Nothing here deletes anything. The only paths that touch the disk are inside one fixture folder
/// this class creates under <c>AppData\Local</c> and removes again — deliberately not under
/// <c>%TEMP%</c>, because %TEMP% is a junk root where every verdict would be level 5 and every
/// interesting rule would be skipped.
/// </para>
/// </summary>
public sealed class DeletionRiskTests : IDisposable
{
    private readonly string _fixture = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "cmw_risk_" + Guid.NewGuid().ToString("N")[..12]);

    public DeletionRiskTests() => Directory.CreateDirectory(_fixture);

    // ============================================================ level 1 tracks the system guard

    public static TheoryData<string> GuardedPaths()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string drive = Path.GetPathRoot(win)!;

        return new TheoryData<string>
        {
            @"C:\",
            "",
            "   ",
            win,
            Path.Combine(win, "System32"),
            Path.Combine(win, "System32", "kernel32.dll"),
            Path.Combine(win, "explorer.exe"),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            home,
            Path.GetDirectoryName(home)!,
            Path.Combine(Path.GetDirectoryName(home)!, "SomeOtherAccount"),
            Path.Combine(home, "Desktop"),
            Path.Combine(home, "Documents"),
            Path.Combine(home, "Downloads"),
            Path.Combine(home, "AppData"),
            Path.Combine(home, "AppData", "Local"),
            Path.Combine(home, "AppData", "Roaming"),
            Path.Combine(drive, "pagefile.sys"),
            Path.Combine(drive, "hiberfil.sys"),
            Path.Combine(drive, "bootmgr"),
            Path.Combine(drive, "Boot"),
            Path.Combine(drive, "EFI"),
            Path.Combine(drive, "Recovery"),
            Path.Combine(drive, "$Recycle.Bin"),
            Path.Combine(drive, "System Volume Information"),
            @"\\?\C:\Windows\System32",
            @"\\localhost\C$\Windows",
            @"C:\Users\me\Documents\*",
            win + "::$INDEX_ALLOCATION",
        };
    }

    /// <summary>
    /// The ramp's floor is the guard, not a second opinion about it. If these ever disagree, the
    /// treemap is painting something amber that the app will then refuse to delete.
    /// </summary>
    [Theory]
    [MemberData(nameof(GuardedPaths))]
    public void Anything_the_system_guard_refuses_is_level_one(string path)
    {
        Assert.True(SystemPathGuard.IsProtected(path, out _), $"Test data is wrong: '{path}' is not guarded");

        foreach (bool isDirectory in new[] { true, false })
        {
            RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory);
            Assert.Equal(DeletionRisk.System, assessment.Level);
        }
    }

    /// <summary>
    /// The converse as well: level 1 means the guard refused it and nothing else does. A rule that
    /// quietly promoted an ordinary folder to "system" would hide the user's own data from the
    /// filter with no way to get it back.
    /// </summary>
    [Fact]
    public void Level_one_and_the_guard_are_the_same_set()
    {
        foreach (string path in AllSamplePaths())
        {
            bool guarded = SystemPathGuard.IsProtected(path, out _);
            bool system = DeletionRiskAssessor.Assess(path, isDirectory: false).Level == DeletionRisk.System;

            Assert.True(guarded == system,
                $"'{path}': guard says protected={guarded} but the ramp says system={system}");
        }
    }

    // ================================================================== the four required verdicts

    [Fact]
    public void A_leftover_file_in_the_temp_folder_is_safe()
    {
        string temp = Path.GetTempPath();

        AssertLevel(DeletionRisk.Safe, Path.Combine(temp, "cmw-not-a-real-file.tmp"), isDirectory: false);
        AssertLevel(DeletionRisk.Safe, Path.Combine(temp, "cmw-no-such-folder", "blob.bin"), isDirectory: false);
        AssertLevel(DeletionRisk.Safe, Path.Combine(temp, "cmw-no-such-folder"), isDirectory: true);
    }

    [Fact]
    public void A_document_in_Documents_needs_caution()
    {
        string documents = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");

        AssertLevel(DeletionRisk.Caution, Path.Combine(documents, "cmw-not-a-real-file.docx"), isDirectory: false);
        AssertLevel(DeletionRisk.Caution, Path.Combine(documents, "taxes", "2024.xlsx"), isDirectory: false);

        // By location as well as by name: a file type we have never heard of is still the user's.
        AssertLevel(DeletionRisk.Caution, Path.Combine(documents, "notes", "thing.qqq"), isDirectory: false);
    }

    [Theory]
    [InlineData(@"C:\cmw-no-such-root\project\node_modules")]
    [InlineData(@"C:\cmw-no-such-root\project\node_modules\some-package")]
    [InlineData(@"C:\cmw-no-such-root\project\bin")]
    [InlineData(@"C:\cmw-no-such-root\project\obj\Debug")]
    [InlineData(@"C:\cmw-no-such-root\project\target")]
    [InlineData(@"C:\cmw-no-such-root\project\.gradle")]
    [InlineData(@"C:\cmw-no-such-root\project\__pycache__")]
    [InlineData(@"C:\cmw-no-such-root\project\.venv\Lib")]
    public void Build_output_is_probably_safe(string path)
        => AssertLevel(DeletionRisk.ProbablySafe, path, isDirectory: true);

    /// <summary>
    /// Build output stays level 4 all the way down. Its executables are the user's own compiler
    /// output, not an installed program, and its bundled images are a package's icons, not photos —
    /// so neither the level 2 nor the level 3 name rule applies inside one.
    /// </summary>
    [Theory]
    [InlineData(@"C:\cmw-no-such-root\project\bin\Debug\app.exe")]
    [InlineData(@"C:\cmw-no-such-root\project\bin\Debug\app.dll")]
    [InlineData(@"C:\cmw-no-such-root\project\node_modules\pkg\index.js")]
    [InlineData(@"C:\cmw-no-such-root\project\node_modules\pkg\logo.png")]
    public void Nothing_inside_build_output_is_treated_as_precious(string path)
        => AssertLevel(DeletionRisk.ProbablySafe, path, isDirectory: false);

    /// <summary>
    /// The one that must never go wrong. Whether the guard refuses it outright or the ramp merely
    /// calls it risky is an implementation detail; painting it green is not.
    /// </summary>
    [Theory]
    [InlineData("SomeVendor", "SomeApp", "app.exe")]
    [InlineData("SomeVendor", "SomeApp", "core.dll")]
    [InlineData("SomeVendor", "SomeApp", "data.bin")]
    [InlineData("SomeVendor", "SomeApp")]
    public void An_executable_inside_Program_Files_is_never_marked_safe(params string[] parts)
    {
        foreach (var folder in new[]
                 {
                     Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86,
                 })
        {
            string path = Path.Combine([Environment.GetFolderPath(folder), .. parts]);
            RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory: false);

            Assert.True((int)assessment.Level <= (int)DeletionRisk.Risky,
                $"'{path}' came back as {assessment.Level}, which the user could delete by mistake");
        }
    }

    // ============================================================================ the middle bands

    [Theory]
    [InlineData(@"D:\Dropbox\notes.txt")]
    [InlineData(@"D:\Google Drive\photos\raw.cr2")]
    [InlineData(@"E:\My Drive\budget.xlsx")]
    [InlineData(@"E:\iCloudDrive\thesis.docx")]
    [InlineData(@"C:\OneDrive - Contoso\report.docx")]
    public void Cloud_synced_content_is_risky_because_deleting_it_deletes_the_cloud_copy(string path)
    {
        RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory: false);

        Assert.Equal(DeletionRisk.Risky, assessment.Level);
        Assert.Contains("sync", assessment.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cloud", assessment.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Roaming_app_data_is_risky_because_it_holds_settings_and_licences()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        AssertLevel(DeletionRisk.Risky,
            Path.Combine(home, "AppData", "Roaming", "cmw-no-vendor", "licence.dat"), isDirectory: false);
        AssertLevel(DeletionRisk.Risky,
            Path.Combine(home, "AppData", "Roaming", "cmw-no-vendor"), isDirectory: true);
        AssertLevel(DeletionRisk.Risky,
            Path.Combine(home, "AppData", "Local", "Programs", "cmw-no-vendor", "app.exe"), isDirectory: false);
    }

    [Theory]
    [InlineData(@"D:\Tools\portable\thing.exe")]
    [InlineData(@"D:\Tools\portable\core.dll")]
    [InlineData(@"D:\drivers\audio.sys")]
    [InlineData(@"C:\cmw-no-such-root\setup.msi")]
    public void Program_files_are_risky_wherever_they_sit(string path)
        => AssertLevel(DeletionRisk.Risky, path, isDirectory: false);

    [Fact]
    public void Downloads_are_probably_safe_including_installers_already_run()
    {
        string downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        AssertLevel(DeletionRisk.ProbablySafe, Path.Combine(downloads, "cmw-setup.exe"), isDirectory: false);
        AssertLevel(DeletionRisk.ProbablySafe, Path.Combine(downloads, "cmw-setup.msi"), isDirectory: false);
        AssertLevel(DeletionRisk.ProbablySafe, Path.Combine(downloads, "cmw-archive.zip"), isDirectory: false);

        // …but a document you downloaded and kept is still a document.
        AssertLevel(DeletionRisk.Caution, Path.Combine(downloads, "contract.pdf"), isDirectory: false);
    }

    [Theory]
    [InlineData(@"C:\cmw-no-such-root\app\install.log")]
    [InlineData(@"C:\cmw-no-such-root\app\trace.etl")]
    [InlineData(@"C:\cmw-no-such-root\app\crash.dmp")]
    [InlineData(@"C:\cmw-no-such-root\app\Cache\entry_00")]
    [InlineData(@"C:\cmw-no-such-root\app\Logs\yesterday")]
    public void Logs_and_caches_are_probably_safe(string path)
        => AssertLevel(DeletionRisk.ProbablySafe, path, isDirectory: false);

    /// <summary>
    /// A disk visualiser exists to show people folders they have never seen. "We cannot tell" has to
    /// read as amber — an unrecognised item promoted to green is exactly how a filter set to
    /// "safe only" would end up offering somebody's game saves.
    /// </summary>
    [Theory]
    [InlineData(@"D:\Games\SomeGame\data.pak")]
    [InlineData(@"D:\Games\SomeGame\saves\slot1.sav")]
    [InlineData(@"C:\cmw-no-such-root\whatever")]
    public void Anything_unrecognised_is_caution_never_probably_safe(string path)
        => AssertLevel(DeletionRisk.Caution, path, isDirectory: false);

    // ============================================================== a folder never looks too safe

    /// <summary>
    /// The rule from the class remarks, exercised on real folders: a folder is lowered to the worst
    /// level any file directly inside it earns. Only the immediate children are read, so this asserts
    /// exactly that and nothing deeper.
    /// </summary>
    [Fact]
    public void A_folder_is_never_shown_as_safer_than_the_files_directly_inside_it()
    {
        Write("programish", "tool.exe");
        Write("programish", "readme.txt");
        Write("Cache", "entry_00");
        Write("Cache", "notes.docx");
        Write("plain", "list.txt");
        Write("logsy", "run.log");

        foreach (string folder in Directory.EnumerateDirectories(_fixture))
        {
            DeletionRisk folderLevel = DeletionRiskAssessor.Assess(folder, isDirectory: true).Level;

            foreach (string file in Directory.EnumerateFiles(folder))
            {
                DeletionRisk fileLevel = DeletionRiskAssessor.Assess(file, isDirectory: false).Level;

                Assert.True((int)folderLevel <= (int)fileLevel,
                    $"'{folder}' is {folderLevel} but holds '{Path.GetFileName(file)}' at {fileLevel}");
            }
        }
    }

    [Fact]
    public void A_folder_holding_an_executable_is_pulled_down_to_risky()
    {
        string folder = Write("appish", "thing.exe");

        RiskAssessment assessment = DeletionRiskAssessor.Assess(folder, isDirectory: true);

        Assert.Equal(DeletionRisk.Risky, assessment.Level);
        Assert.Contains("thing.exe", assessment.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_cache_folder_holding_a_document_is_pulled_down_to_caution()
    {
        string folder = Write("Cache", "invoice.pdf");

        // Empty, the same folder name is level 4 — the document inside it is what lowers it.
        Assert.Equal(DeletionRisk.ProbablySafe,
            DeletionRiskAssessor.Assess(Path.Combine(_fixture, "cmw-absent", "Cache"), isDirectory: true).Level);

        Assert.Equal(DeletionRisk.Caution, DeletionRiskAssessor.Assess(folder, isDirectory: true).Level);
    }

    // ==================================================================================== the API

    /// <summary>
    /// The filter reads "show me everything at least this safe", so the comparison has to run the
    /// opposite way to the numbers. Getting this backwards would show the user exactly the items
    /// they asked to hide.
    /// </summary>
    [Theory]
    [InlineData(DeletionRisk.Safe, DeletionRisk.Safe, true)]
    [InlineData(DeletionRisk.ProbablySafe, DeletionRisk.Safe, false)]
    [InlineData(DeletionRisk.System, DeletionRisk.Safe, false)]
    [InlineData(DeletionRisk.Safe, DeletionRisk.Caution, true)]
    [InlineData(DeletionRisk.Caution, DeletionRisk.Caution, true)]
    [InlineData(DeletionRisk.Risky, DeletionRisk.Caution, false)]
    [InlineData(DeletionRisk.System, DeletionRisk.System, true)]
    [InlineData(DeletionRisk.Safe, DeletionRisk.System, true)]
    public void IsAtOrBelow_means_at_least_this_safe(DeletionRisk level, DeletionRisk threshold, bool expected)
        => Assert.Equal(expected, DeletionRiskAssessor.IsAtOrBelow(level, threshold));

    [Fact]
    public void The_widest_threshold_shows_everything_and_the_narrowest_shows_only_junk()
    {
        Assert.All(DeletionRiskAssessor.Levels,
            level => Assert.True(DeletionRiskAssessor.IsAtOrBelow(level, DeletionRisk.System)));

        Assert.Equal(
            [DeletionRisk.Safe],
            DeletionRiskAssessor.Levels.Where(l => DeletionRiskAssessor.IsAtOrBelow(l, DeletionRisk.Safe)));
    }

    [Fact]
    public void Every_level_has_a_label_and_a_description_and_the_ramp_is_ordered()
    {
        Assert.Equal(5, DeletionRiskAssessor.Levels.Count);
        Assert.Equal([1, 2, 3, 4, 5], DeletionRiskAssessor.Levels.Select(l => (int)l));

        foreach (DeletionRisk level in DeletionRiskAssessor.Levels)
        {
            Assert.False(string.IsNullOrWhiteSpace(DeletionRiskAssessor.ShortLabel(level)));
            Assert.False(string.IsNullOrWhiteSpace(DeletionRiskAssessor.Describe(level)));
            Assert.EndsWith(".", DeletionRiskAssessor.Describe(level), StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Every verdict is shown to somebody, so every verdict needs a headline and a whole sentence.
    /// A blank reason next to a delete button is worse than no dialog at all.
    /// </summary>
    [Fact]
    public void Every_verdict_carries_a_headline_and_a_finished_sentence()
    {
        foreach (string path in AllSamplePaths())
        {
            foreach (bool isDirectory in new[] { true, false })
            {
                RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory);

                Assert.False(string.IsNullOrWhiteSpace(assessment.Title), $"No title for '{path}'");
                Assert.False(string.IsNullOrWhiteSpace(assessment.Reason), $"No reason for '{path}'");
                Assert.EndsWith(".", assessment.Reason.Trim(), StringComparison.Ordinal);

                // A sentence may legitimately open with a quoted name — “Desktop” is one of your
                // main folders. reads better than the alternative, because it says which folder
                // before it says anything else. So skip any opening quotation mark before
                // checking capitalisation rather than forcing the wording to start with a letter.
                string sentence = assessment.Reason.Trim().TrimStart('“', '‘', '"', '\'');

                Assert.True(
                    sentence.Length > 0 && char.IsUpper(sentence[0]),
                    $"Reason for '{path}' does not start a sentence: {assessment.Reason}");
            }
        }
    }

    /// <summary>
    /// <see cref="DeletionRiskAssessor.Assess"/> runs on every node of a treemap, including ones the
    /// user only hovers past, so it has to survive anything — and whatever it cannot read must come
    /// back as level 1, never as something the filter would offer up as safe.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("::::")]
    [InlineData(@"C:\|pipe")]
    [InlineData("C:\\Users\\me\\a\0b.txt")]
    [InlineData(@"nul")]
    [InlineData(@"CON")]
    [InlineData(@"\\server\share\anything.txt")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"C:\Users\me\a<b>c")]
    public void Never_throws_on_hostile_input_and_falls_back_to_level_one(string path)
    {
        RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory: false);

        Assert.Equal(DeletionRisk.System, assessment.Level);
        Assert.False(string.IsNullOrWhiteSpace(assessment.Reason));
    }

    // ==================================================================================== helpers

    private static void AssertLevel(DeletionRisk expected, string path, bool isDirectory)
    {
        RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory);
        Assert.True(expected == assessment.Level,
            $"'{path}' was rated {assessment.Level} ({assessment.Reason}), expected {expected}");
    }

    /// <summary>Creates <c>fixture\folder\file</c> with a byte in it and returns the folder.</summary>
    private string Write(string folder, string file)
    {
        string directory = Path.Combine(_fixture, folder);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, file), "x");
        return directory;
    }

    /// <summary>A spread of paths wide enough to be worth asserting a contract over.</summary>
    private static IEnumerable<string> AllSamplePaths()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // TheoryData<string> enumerates as string on this xUnit version, not as object[].
        foreach (string path in GuardedPaths()) yield return path;

        yield return Path.Combine(Path.GetTempPath(), "cmw-not-a-real-file.tmp");
        yield return Path.Combine(home, "Documents", "cmw-not-a-real-file.docx");
        yield return Path.Combine(home, "Downloads", "cmw-setup.exe");
        yield return Path.Combine(home, "AppData", "Roaming", "cmw-no-vendor", "licence.dat");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SomeVendor", "SomeApp", "app.exe");
        yield return @"C:\cmw-no-such-root\project\node_modules";
        yield return @"C:\cmw-no-such-root\app\install.log";
        yield return @"D:\Dropbox\notes.txt";
        yield return @"D:\Games\SomeGame\data.pak";
        yield return @"D:\Tools\portable\thing.exe";
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_fixture)) Directory.Delete(_fixture, recursive: true);
        }
        catch (Exception)
        {
            // A leftover fixture folder is a smaller problem than a throwing teardown.
        }
    }
}
