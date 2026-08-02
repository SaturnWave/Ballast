using Ballast.Core.Startup;
using Microsoft.Win32;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Verifies that disabling a startup item is genuinely <b>reversible</b> — the headline safety
/// claim of the startup manager. Rather than trusting that the value "moves", these tests write a
/// real throwaway entry into <c>HKCU\...\Run</c>, round-trip it through the toggle service, and
/// assert the exact registry state at each step.
///
/// <para>
/// Everything happens under HKEY_CURRENT_USER (no elevation) using a GUID-suffixed value name that
/// cannot collide with a real program, and <see cref="Dispose"/> removes it from both the live and
/// the disabled key even if an assertion fails.
/// </para>
/// </summary>
public sealed class StartupToggleTests : IDisposable
{
    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string DisabledRunPath = RunPath + "-disabled-Ballast";

    private readonly string _valueName = "BallastTest_" + Guid.NewGuid().ToString("N")[..8];
    private const string CommandLine = @"C:\Windows\System32\cmd.exe /c rem Ballast-test";

    public StartupToggleTests()
    {
        using var run = Registry.CurrentUser.CreateSubKey(RunPath, writable: true)!;
        run.SetValue(_valueName, CommandLine, RegistryValueKind.String);
    }

    public void Dispose()
    {
        foreach (var path in new[] { RunPath, DisabledRunPath })
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path, writable: true);
                if (key?.GetValue(_valueName) is not null) key.DeleteValue(_valueName, throwOnMissingValue: false);
            }
            catch
            {
                // Cleanup is best effort; a leftover test value is harmless and inert.
            }
        }
    }

    private static string? Read(string path, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path);
        return key?.GetValue(name) as string;
    }

    private StartupEntry Entry(bool enabled) => new()
    {
        Name = _valueName,
        Command = CommandLine,
        Source = StartupSource.RegistryRunHkcu,
        IsEnabled = enabled,
        RequiresAdmin = false,
        Location = @"HKCU\" + RunPath,
    };

    [Fact]
    public void The_test_fixture_really_created_a_run_entry()
        => Assert.Equal(CommandLine, Read(RunPath, _valueName));

    [Fact]
    public async Task Disabling_moves_the_value_to_the_backup_key_without_destroying_it()
    {
        await new StartupToggleService().SetEnabledAsync(Entry(enabled: true), enabled: false);

        Assert.Null(Read(RunPath, _valueName));                       // gone from autostart
        Assert.Equal(CommandLine, Read(DisabledRunPath, _valueName)); // preserved verbatim
    }

    [Fact]
    public async Task Re_enabling_restores_the_original_command_exactly()
    {
        var service = new StartupToggleService();

        await service.SetEnabledAsync(Entry(enabled: true), enabled: false);
        Assert.Null(Read(RunPath, _valueName));

        await service.SetEnabledAsync(Entry(enabled: false), enabled: true);

        Assert.Equal(CommandLine, Read(RunPath, _valueName));
        Assert.Null(Read(DisabledRunPath, _valueName)); // no duplicate left behind
    }

    [Fact]
    public async Task A_full_round_trip_leaves_the_registry_exactly_as_it_started()
    {
        var before = Read(RunPath, _valueName);
        var service = new StartupToggleService();

        await service.SetEnabledAsync(Entry(enabled: true), enabled: false);
        await service.SetEnabledAsync(Entry(enabled: false), enabled: true);

        Assert.Equal(before, Read(RunPath, _valueName));
    }

    [Fact]
    public async Task The_scanner_still_reports_a_disabled_entry_so_it_can_be_switched_back_on()
    {
        await new StartupToggleService().SetEnabledAsync(Entry(enabled: true), enabled: false);

        var entries = await new StartupScanner { IncludeScheduledTasks = false }.ScanFastAsync();
        var mine = entries.FirstOrDefault(e => e.Name == _valueName);

        Assert.NotNull(mine);
        Assert.False(mine!.IsEnabled);
    }

    [Fact]
    public async Task Disabling_twice_is_idempotent_rather_than_an_error()
    {
        var service = new StartupToggleService();

        await service.SetEnabledAsync(Entry(enabled: true), enabled: false);
        await service.SetEnabledAsync(Entry(enabled: false), enabled: false);

        Assert.Equal(CommandLine, Read(DisabledRunPath, _valueName));
        Assert.Null(Read(RunPath, _valueName));
    }

    [Fact]
    public void CanToggle_allows_a_current_user_entry_without_elevation()
    {
        var can = new StartupToggleService().CanToggle(Entry(enabled: true), out var reason);

        Assert.True(can, reason);
        Assert.Null(reason);
    }

    [Fact]
    public void CanToggle_refuses_a_machine_wide_entry_when_not_elevated_and_explains_why()
    {
        var hklm = new StartupEntry
        {
            Name = "SomeMachineWideThing",
            Command = @"C:\Program Files\Thing\thing.exe",
            Source = StartupSource.RegistryRunHklm,
            IsEnabled = true,
            RequiresAdmin = true,
            Location = @"HKLM\" + RunPath,
        };

        var can = new StartupToggleService().CanToggle(hklm, out var reason);

        if (Ballast.Core.Util.Elevation.IsElevated)
        {
            Assert.True(can);
        }
        else
        {
            Assert.False(can);
            Assert.False(string.IsNullOrWhiteSpace(reason));
            Assert.Contains("administrator", reason!, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <remarks>
    /// For registry entries the target key is derived from the <see cref="StartupSource"/> enum,
    /// never from the free-text <see cref="StartupEntry.Location"/>. That is deliberately stronger
    /// than validating <c>Location</c>: a closed enum cannot be pointed at an arbitrary key, so
    /// there is no string for a caller to forge. This test pins that behaviour — a nonsense
    /// <c>Location</c> must neither redirect the write nor abort it.
    /// </remarks>
    [Fact]
    public async Task A_registry_write_follows_the_source_enum_not_the_location_string()
    {
        var misleading = new StartupEntry
        {
            Name = _valueName,
            Command = CommandLine,
            Source = StartupSource.RegistryRunHkcu,
            IsEnabled = true,
            RequiresAdmin = false,
            Location = @"HKCU\Software\Something\Else\Entirely",
        };

        await new StartupToggleService().SetEnabledAsync(misleading, enabled: false);

        // It acted on the real HKCU Run key, as the Source says...
        Assert.Null(Read(RunPath, _valueName));
        Assert.Equal(CommandLine, Read(DisabledRunPath, _valueName));

        // ...and did not create anything at the bogus path.
        using var bogus = Registry.CurrentUser.OpenSubKey(@"Software\Something\Else\Entirely");
        Assert.Null(bogus);
    }

    /// <summary>
    /// Startup-folder entries <em>do</em> carry a real filesystem path, so that is where a scope
    /// check is needed: a file may only ever move between the Startup folder the entry claims and
    /// our own disabled subfolder of it. Anything else must be refused outright.
    /// </summary>
    [Fact]
    public async Task A_startup_folder_entry_pointing_outside_the_startup_folder_is_refused()
    {
        // A real file we would be very upset to see moved.
        var victim = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            $"Ballast-must-not-move-{Guid.NewGuid():N}.lnk");
        File.WriteAllText(victim, "not a startup item");

        var forged = new StartupEntry
        {
            Name = Path.GetFileNameWithoutExtension(victim),
            Command = victim,
            Source = StartupSource.StartupFolderUser,
            IsEnabled = true,
            RequiresAdmin = false,
            Location = victim,
        };

        try
        {
            await Assert.ThrowsAnyAsync<Exception>(
                () => new StartupToggleService().SetEnabledAsync(forged, enabled: false));

            Assert.True(File.Exists(victim), "a file outside the Startup folder was moved!");
        }
        finally
        {
            File.Delete(victim);
        }
    }
}
