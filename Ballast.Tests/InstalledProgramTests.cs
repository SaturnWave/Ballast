using Ballast.Core.Programs;
using Ballast.Core.Util;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Tests for the installed-programs list and the uninstall launcher.
///
/// <para>
/// <b>Nothing here runs an uninstaller.</b> <see cref="UninstallLauncher.LaunchAsync"/> is never
/// called: it starts a real vendor uninstaller, which is exactly the kind of thing a test suite
/// must not do to the machine it runs on. Everything below exercises the pure functions around it —
/// the command-line split, the size and date conversions, the filter and the de-duplication — plus
/// one read-only pass over the real registry.
/// </para>
///
/// <para>
/// The parsing tests matter more than they look. A quoted path split on whitespace yields
/// <c>C:\Program</c>, and handing that to the shell either fails outright or runs whatever happens
/// to be sitting at that name. The size tests matter for a quieter reason: <c>EstimatedSize</c> is
/// absent far more often than it is present, and a zero read as a measurement makes the list tell
/// the user that a 4 GB program takes no space.
/// </para>
///
/// <para>
/// The one path that touches the disk is a fixture folder this class creates under
/// <c>AppData\Local</c> and removes again. It holds a single empty file, which exists only so that
/// <see cref="UninstallLauncher.ParseCommand"/> has a real unquoted path with spaces in it to
/// resolve. Nothing in it is ever executed.
/// </para>
/// </summary>
public sealed class InstalledProgramTests : IDisposable
{
    private readonly string _fixture = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ballast_apps_" + Guid.NewGuid().ToString("N")[..12]);

    private readonly string _fixtureUninstaller;

    public InstalledProgramTests()
    {
        // A space in the folder name on purpose: that is the case the parser has to get right.
        string folder = Path.Combine(_fixture, "Some App");
        Directory.CreateDirectory(folder);

        _fixtureUninstaller = Path.Combine(folder, "unins000.exe");
        File.WriteAllBytes(_fixtureUninstaller, []);
    }

    public void Dispose()
    {
        try { Directory.Delete(_fixture, recursive: true); }
        catch { /* the test run is over; a leftover fixture folder is not worth failing for */ }
    }

    // ============================================================ EstimatedSize: KB to bytes

    [Fact]
    public void EstimatedSize_IsInterpretedAsKilobytes()
    {
        Assert.Equal(1024L, InstalledProgramScanner.EstimatedSizeToBytes(1));
        Assert.Equal(1024L * 1024, InstalledProgramScanner.EstimatedSizeToBytes(1024));
        Assert.Equal(250_000L * 1024, InstalledProgramScanner.EstimatedSizeToBytes(250_000));
    }

    [Fact]
    public void EstimatedSize_OfZero_IsUnknownRatherThanZeroBytes()
    {
        // The whole point: 0 means "the installer did not record a size", not "it takes no space".
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(0));
    }

    [Fact]
    public void EstimatedSize_MissingOrUnusable_IsNull()
    {
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(null));
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(""));
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes("not a number"));
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(new object()));
    }

    [Fact]
    public void EstimatedSize_WrittenAsAString_IsStillRead()
    {
        // A minority of installers write the number as text rather than as a DWORD.
        Assert.Equal(2048L * 1024, InstalledProgramScanner.EstimatedSizeToBytes("2048"));
        Assert.Equal(2048L * 1024, InstalledProgramScanner.EstimatedSizeToBytes("  2048  "));
    }

    [Fact]
    public void EstimatedSize_ThatIsGarbage_IsUnknownRatherThanTerabytes()
    {
        // 0xFFFFFFFF read as a signed DWORD is -1. Reinterpreted as unsigned it is 4.4 TB, which
        // is not a program, so it has to come back as unknown rather than be shown.
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(-1));
        Assert.Null(InstalledProgramScanner.EstimatedSizeToBytes(int.MinValue));
    }

    [Fact]
    public void EstimatedSize_JustBelowTheImplausibleCeiling_IsStillReported()
    {
        long kilobytes = (InstalledProgramScanner.ImplausibleProgramSizeBytes / 1024) - 1;

        Assert.Equal(kilobytes * 1024, InstalledProgramScanner.EstimatedSizeToBytes(kilobytes));
    }

    // ============================================================ SizeDisplay

    [Fact]
    public void SizeDisplay_IsAnEmDash_WhenTheSizeIsUnknown()
    {
        InstalledProgram program = MakeProgram("Something", sizeBytes: null);

        Assert.Equal("\u2014", program.SizeDisplay);
        Assert.DoesNotContain("0 KB", program.SizeDisplay);
    }

    [Fact]
    public void SizeDisplay_UsesTheSharedFormatter_WhenTheSizeIsKnown()
    {
        InstalledProgram program = MakeProgram("Something", sizeBytes: 1_500_000_000);

        Assert.Equal(ByteFormatter.Format(1_500_000_000), program.SizeDisplay);
    }

    // ============================================================ RequiresAdmin

    [Theory]
    [InlineData(ProgramScope.CurrentUser, false)]
    [InlineData(ProgramScope.AllUsers, true)]
    [InlineData(ProgramScope.AllUsers32Bit, true)]
    public void RequiresAdmin_TracksTheScope(ProgramScope scope, bool expected)
    {
        Assert.Equal(expected, MakeProgram("Something", scope: scope).RequiresAdmin);
    }

    // ============================================================ InstallDate

    [Fact]
    public void InstallDate_ReadsTheDocumentedYyyyMmDdForm()
    {
        Assert.Equal(new DateOnly(2024, 1, 15), InstalledProgramScanner.ParseInstallDate("20240115"));

        // Some installers store it as a number rather than as a string.
        Assert.Equal(new DateOnly(2024, 1, 15), InstalledProgramScanner.ParseInstallDate(20240115));
    }

    [Fact]
    public void InstallDate_ThatIsMissingOrNonsense_IsNull()
    {
        Assert.Null(InstalledProgramScanner.ParseInstallDate(null));
        Assert.Null(InstalledProgramScanner.ParseInstallDate(""));
        Assert.Null(InstalledProgramScanner.ParseInstallDate("   "));
        Assert.Null(InstalledProgramScanner.ParseInstallDate("not a date"));

        // Parses cleanly and is still junk, so it must not be presented as an install date.
        Assert.Null(InstalledProgramScanner.ParseInstallDate("00010101"));
    }

    // ============================================================ the filter Add or Remove Programs applies

    [Fact]
    public void AnOrdinaryProgram_IsListed()
    {
        Assert.False(
            InstalledProgramScanner.ShouldHide(
                new UninstallKeyValues
                {
                    DisplayName = "Notepad++",
                    UninstallString = @"C:\Program Files\Notepad++\uninstall.exe",
                },
                out string? reason));

        Assert.Null(reason);
    }

    [Fact]
    public void AnEntryWithNoDisplayName_IsHidden()
    {
        Assert.Contains("DisplayName", HiddenReason(new UninstallKeyValues { UninstallString = "whatever.exe" }));

        // Whitespace counts as absent.
        Assert.Contains("DisplayName", HiddenReason(new UninstallKeyValues { DisplayName = "   " }));
    }

    [Theory]
    [InlineData("KB2999226")]
    [InlineData("kb5001234")]
    [InlineData("KB4562830 (Update for Microsoft Windows)")]
    public void HotfixNames_AreHidden(string name)
    {
        Assert.Contains(
            "hotfix",
            HiddenReason(new UninstallKeyValues { DisplayName = name, UninstallString = "x.exe" }));
    }

    [Theory]
    [InlineData("KBase Editor")]
    [InlineData("KB Toolkit")]
    [InlineData("KB")]
    public void RealProgramsWhoseNamesMerelyStartWithThoseLetters_AreListed(string name)
    {
        // The digit test is the whole reason the hotfix rule is safe to apply to a display name.
        Assert.False(
            InstalledProgramScanner.ShouldHide(
                new UninstallKeyValues { DisplayName = name, UninstallString = "x.exe" }, out _));
    }

    [Fact]
    public void SystemComponents_AreHidden()
    {
        Assert.Contains(
            "SystemComponent",
            HiddenReason(new UninstallKeyValues
            {
                DisplayName = "Microsoft Visual C++ 2015 Redistributable",
                UninstallString = "MsiExec.exe /X{1234}",
                SystemComponent = 1,
            }));
    }

    [Fact]
    public void SystemComponentOfZero_DoesNotHideAnything()
    {
        Assert.False(
            InstalledProgramScanner.ShouldHide(
                new UninstallKeyValues
                {
                    DisplayName = "A Real Program",
                    UninstallString = "x.exe",
                    SystemComponent = 0,
                },
                out _));
    }

    [Theory]
    [InlineData("Update")]
    [InlineData("Hotfix")]
    [InlineData("Security Update")]
    [InlineData("security update")]
    public void UpdateReleaseTypes_AreHidden(string releaseType)
    {
        Assert.True(
            InstalledProgramScanner.ShouldHide(
                new UninstallKeyValues
                {
                    DisplayName = "Some Product Patch",
                    UninstallString = "x.exe",
                    ReleaseType = releaseType,
                },
                out _));
    }

    [Fact]
    public void ChildEntriesOfAnotherProduct_AreHidden()
    {
        Assert.Contains(
            "ParentKeyName",
            HiddenReason(new UninstallKeyValues
            {
                DisplayName = "Office Language Pack",
                UninstallString = "x.exe",
                ParentKeyName = "{90160000-0011-0000-0000-0000000FF1CE}",
            }));
    }

    [Fact]
    public void MsiEntriesWithNothingToRun_AreHidden()
    {
        Assert.Contains(
            "UninstallString",
            HiddenReason(new UninstallKeyValues { DisplayName = "An MSI Component", WindowsInstaller = 1 }));

        // The same entry with a command to run is a real product.
        Assert.False(
            InstalledProgramScanner.ShouldHide(
                new UninstallKeyValues
                {
                    DisplayName = "An MSI Product",
                    WindowsInstaller = 1,
                    UninstallString = "MsiExec.exe /X{1234}",
                },
                out _));
    }

    // ============================================================ uninstall command parsing

    [Fact]
    public void AQuotedPathWithArguments_SplitsAtTheClosingQuote()
    {
        UninstallCommandLine line =
            UninstallLauncher.ParseCommand("\"C:\\Program Files\\Some App\\unins000.exe\" /SILENT /NORESTART");

        // The classic bug here is splitting on the first space and getting "C:\Program".
        Assert.Equal(@"C:\Program Files\Some App\unins000.exe", line.Executable);
        Assert.Equal("/SILENT /NORESTART", line.Arguments);
        Assert.True(line.IsUsable);
    }

    [Fact]
    public void AQuotedPathWithNoArguments_HasNoArguments()
    {
        UninstallCommandLine line =
            UninstallLauncher.ParseCommand("\"C:\\Program Files\\Some App\\unins000.exe\"");

        Assert.Equal(@"C:\Program Files\Some App\unins000.exe", line.Executable);
        Assert.Equal(string.Empty, line.Arguments);
    }

    [Fact]
    public void AnUnquotedPathContainingSpaces_IsSplitAtTheExecutable_WhenItExists()
    {
        UninstallCommandLine line = UninstallLauncher.ParseCommand($"{_fixtureUninstaller} /S");

        // The file is really there, so the filesystem is what decides where the path ends.
        Assert.Equal(_fixtureUninstaller, line.Executable);
        Assert.Equal("/S", line.Arguments);
    }

    [Fact]
    public void AnUnquotedPathContainingSpaces_IsSplitAtTheExecutable_EvenWhenItIsGone()
    {
        // A stale registry entry left behind by an earlier uninstall. Nothing exists to probe, so
        // the extension has to arbitrate rather than the first space.
        UninstallCommandLine line =
            UninstallLauncher.ParseCommand(@"C:\Program Files\Gone Away\unins000.exe /S");

        Assert.Equal(@"C:\Program Files\Gone Away\unins000.exe", line.Executable);
        Assert.Equal("/S", line.Arguments);
    }

    [Fact]
    public void AnMsiExecCommand_KeepsTheProductCodeAsAnArgument()
    {
        UninstallCommandLine line =
            UninstallLauncher.ParseCommand("MsiExec.exe /X{2E4E1F0F-2E4E-4E4E-9E4E-2E4E1F0F2E4E}");

        Assert.Equal("MsiExec.exe", line.Executable);
        Assert.Equal("/X{2E4E1F0F-2E4E-4E4E-9E4E-2E4E1F0F2E4E}", line.Arguments);
    }

    [Fact]
    public void AFullyQualifiedMsiExecCommand_ParsesTheSameWay()
    {
        string msiexec = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "msiexec.exe");

        UninstallCommandLine line = UninstallLauncher.ParseCommand($"{msiexec} /x {{1234-5678}} /qn");

        Assert.Equal(msiexec, line.Executable);
        Assert.Equal("/x {1234-5678} /qn", line.Arguments);
    }

    [Fact]
    public void ARundll32Command_KeepsItsCommaSeparatedArguments()
    {
        UninstallCommandLine line = UninstallLauncher.ParseCommand(
            @"rundll32.exe advpack.dll,LaunchINFSection C:\Windows\INF\thing.inf,Uninstall");

        Assert.Equal("rundll32.exe", line.Executable);
        Assert.Equal(@"advpack.dll,LaunchINFSection C:\Windows\INF\thing.inf,Uninstall", line.Arguments);
    }

    [Fact]
    public void ABareCommandWithNoArguments_ParsesToJustTheExecutable()
    {
        UninstallCommandLine line = UninstallLauncher.ParseCommand("unins000.exe");

        Assert.Equal("unins000.exe", line.Executable);
        Assert.Equal(string.Empty, line.Arguments);
        Assert.True(line.IsUsable);
    }

    [Fact]
    public void AnArgumentThatIsItselfAnExecutablePath_DoesNotMoveTheSplit()
    {
        UninstallCommandLine line =
            UninstallLauncher.ParseCommand(@"C:\Gone\setup.exe --uninstall C:\Gone\helper.exe");

        Assert.Equal(@"C:\Gone\setup.exe", line.Executable);
        Assert.Equal(@"--uninstall C:\Gone\helper.exe", line.Arguments);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("    ")]
    public void AnEmptyCommand_IsNotUsable(string? command)
    {
        UninstallCommandLine line = UninstallLauncher.ParseCommand(command);

        Assert.False(line.IsUsable);
        Assert.Equal(string.Empty, line.Executable);
        Assert.Equal(string.Empty, line.Arguments);
    }

    // ============================================================ de-duplication

    [Fact]
    public void Deduplicate_PrefersTheEntryThatCanActuallyUninstall()
    {
        InstalledProgram stub = MakeProgram(
            "Shared App", scope: ProgramScope.AllUsers32Bit, keyName: "{SHARED-GUID}", uninstall: null);

        InstalledProgram real = MakeProgram(
            "Shared App", scope: ProgramScope.AllUsers, keyName: "{SHARED-GUID}",
            uninstall: "MsiExec.exe /X{SHARED-GUID}");

        // Both orders, because the answer must not depend on which registry was read first.
        Assert.Equal(
            "MsiExec.exe /X{SHARED-GUID}",
            Assert.Single(InstalledProgramScanner.Deduplicate(new[] { stub, real })).UninstallCommand);

        Assert.Equal(
            "MsiExec.exe /X{SHARED-GUID}",
            Assert.Single(InstalledProgramScanner.Deduplicate(new[] { real, stub })).UninstallCommand);
    }

    [Fact]
    public void Deduplicate_KeepsDistinctProducts()
    {
        InstalledProgram[] programs =
        [
            MakeProgram("App One", keyName: "{ONE}", uninstall: "one.exe /u"),
            MakeProgram("App Two", keyName: "{TWO}", uninstall: "two.exe /u"),

            // Same display name, different product code: two genuinely separate installations.
            MakeProgram("App Two", keyName: "{THREE}", uninstall: "three.exe /u"),
        ];

        Assert.Equal(3, InstalledProgramScanner.Deduplicate(programs).Count);
    }

    [Fact]
    public void Deduplicate_PrefersTheEntryThatKnowsItsSize_WhenBothCanUninstall()
    {
        InstalledProgram sizeless = MakeProgram("App", keyName: "{K}", uninstall: "u.exe", sizeBytes: null);
        InstalledProgram sized = MakeProgram("App", keyName: "{K}", uninstall: "u.exe", sizeBytes: 5_000_000);

        Assert.Equal(
            5_000_000L,
            Assert.Single(InstalledProgramScanner.Deduplicate(new[] { sizeless, sized })).EstimatedSizeBytes);
    }

    [Fact]
    public void Deduplicate_OrdersByDisplayName()
    {
        InstalledProgram[] programs =
        [
            MakeProgram("Zebra", keyName: "{Z}"),
            MakeProgram("apple", keyName: "{A}"),
            MakeProgram("Mango", keyName: "{M}"),
        ];

        Assert.Equal(
            new[] { "apple", "Mango", "Zebra" },
            InstalledProgramScanner.Deduplicate(programs).Select(p => p.DisplayName).ToArray());
    }

    [Fact]
    public void Deduplicate_OfNothing_IsEmpty()
    {
        Assert.Empty(InstalledProgramScanner.Deduplicate(Array.Empty<InstalledProgram>()));
    }

    // ============================================================ a real, read-only scan

    [Fact]
    public async Task ScanAsync_ReadsTheRealRegistryWithoutChangingAnything()
    {
        // Read-only by construction: every key is opened with writable: false.
        IReadOnlyList<InstalledProgram> programs = await new InstalledProgramScanner().ScanAsync();

        Assert.NotNull(programs);

        foreach (InstalledProgram program in programs)
        {
            Assert.False(string.IsNullOrWhiteSpace(program.DisplayName));
            Assert.False(string.IsNullOrWhiteSpace(program.RegistryKeyPath));

            // Every listed row must have survived the name-based half of the filter.
            Assert.False(
                InstalledProgramScanner.ShouldHide(
                    new UninstallKeyValues
                    {
                        DisplayName = program.DisplayName,
                        UninstallString = program.UninstallCommand,
                    },
                    out _),
                $"'{program.DisplayName}' should have been filtered out.");

            // A zero size must have become "unknown" on the way in, and must never render as a
            // confident zero.
            Assert.True(program.EstimatedSizeBytes is null or > 0);
            Assert.NotEqual("0 KB", program.SizeDisplay);
        }

        // De-duplication happens inside ScanAsync, so no two rows share an identity.
        Assert.Equal(
            programs.Count,
            programs
                .Select(p => $"{p.KeyName}\u001f{p.DisplayName}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count());
    }

    [Fact]
    public void FindRemainingFolders_ReportsOnlyFoldersThatExist()
    {
        string gone = Path.Combine(_fixture, "not-here-" + Guid.NewGuid().ToString("N")[..8]);

        IReadOnlyList<string> remaining = UninstallLauncher.FindRemainingFolders(
        [
            MakeProgram("Present", installLocation: _fixture),
            MakeProgram("Absent", installLocation: gone),
            MakeProgram("Unrecorded", installLocation: null),
        ]);

        // Reported, never removed: this method exists so the UI can show the path and say plainly
        // that Ballast will not touch it. The folder is still there afterwards.
        Assert.Equal(new[] { _fixture }, remaining.ToArray());
        Assert.True(Directory.Exists(_fixture));
    }

    // ============================================================ helpers

    /// <summary>Asserts that <paramref name="values"/> is hidden and returns the stated reason.</summary>
    private static string HiddenReason(UninstallKeyValues values)
    {
        Assert.True(InstalledProgramScanner.ShouldHide(values, out string? reason));
        return reason ?? string.Empty;
    }

    private static InstalledProgram MakeProgram(
        string displayName,
        ProgramScope scope = ProgramScope.AllUsers,
        string? keyName = null,
        string? uninstall = "unins000.exe /S",
        long? sizeBytes = null,
        string? installLocation = null) => new()
        {
            DisplayName = displayName,
            RegistryKeyPath =
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + (keyName ?? displayName),
            Scope = scope,
            UninstallCommand = uninstall,
            EstimatedSizeBytes = sizeBytes,
            InstallLocation = installLocation,
        };
}
