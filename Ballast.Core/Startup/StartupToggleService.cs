using Ballast.Core.Util;
using Microsoft.Win32;

namespace Ballast.Core.Startup;

/// <summary>
/// Turns startup entries off and back on, reversibly.
///
/// Nothing here deletes anything, which is the whole point:
/// <list type="bullet">
///   <item>A Run value is <em>moved</em> into a parallel key we own
///     (<c>...\CurrentVersion\Run-disabled-Ballast</c>) and moved back on re-enable. The
///     copy is written and verified before the original is removed, so the worst failure mode
///     is an entry that briefly exists in both keys.</item>
///   <item>A Startup-folder shortcut is <em>moved</em> into a <c>Disabled-Ballast</c>
///     subfolder of the same Startup folder. Windows never launches items from a subfolder, and
///     the file is untouched. Moves never overwrite: a name clash gets a suffix.</item>
///   <item>A scheduled task is disabled with <c>schtasks /change /tn "..." /disable</c>, which
///     flips the task's Enabled flag and keeps the definition.</item>
/// </list>
///
/// <see cref="PathSafety"/> deliberately does not apply: its allowlist covers junk roots that
/// may be deleted, and this service deletes nothing. The equivalent guard here is the scope
/// check in the folder path — a shortcut is only ever moved between a known Startup folder and
/// our own subfolder of it.
///
/// Entries are immutable, so <see cref="StartupEntry.Location"/> is stale once a move
/// succeeds: rescan with <see cref="StartupScanner"/> after toggling.
/// </summary>
public sealed class StartupToggleService
{
    /// <summary>
    /// True when this entry can be toggled right now. On false, <paramref name="reason"/>
    /// carries a message meant for the user — the machine-wide cases produce the wording the
    /// shell turns into a "Restart as administrator" prompt.
    /// </summary>
    public bool CanToggle(StartupEntry entry, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return Validate(entry, out reason, out _);
    }

    /// <summary>
    /// Moves the entry between its live store and our disabled store (or flips a task's
    /// Enabled flag). No-ops when it is already in the requested state.
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">
    /// The entry is machine-wide and this process is not elevated, or Windows refused the
    /// write. The message is user-facing and asks for a restart as administrator.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The entry has moved or vanished since the scan; the caller should rescan.
    /// </exception>
    public async Task SetEnabledAsync(StartupEntry entry, bool enabled, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if (!Validate(entry, out var reason, out var needsElevation))
        {
            if (needsElevation && !Elevation.IsElevated)
                throw new UnauthorizedAccessException(reason);

            throw new InvalidOperationException(reason ?? "This startup item cannot be changed.");
        }

        ct.ThrowIfCancellationRequested();

        if (entry.Source.IsRegistry())
            await Task.Run(() => ToggleRegistry(entry, enabled), ct).ConfigureAwait(false);
        else if (entry.Source.IsStartupFolder())
            await Task.Run(() => ToggleStartupFolder(entry, enabled), ct).ConfigureAwait(false);
        else if (entry.Source is StartupSource.ScheduledTask)
            await ToggleScheduledTaskAsync(entry, enabled, ct).ConfigureAwait(false);
        else
            throw new NotSupportedException($"Ballast cannot change a {entry.Source} startup entry.");
    }

    /// <summary>
    /// Shared gate for <see cref="CanToggle"/> and <see cref="SetEnabledAsync"/> so the button
    /// state and the actual attempt can never disagree.
    /// </summary>
    private static bool Validate(StartupEntry entry, out string? reason, out bool needsElevation)
    {
        needsElevation = entry.RequiresAdmin || entry.Source.RequiresAdmin();

        if (needsElevation && !Elevation.IsElevated)
        {
            reason =
                $"“{entry.DisplayName}” is a machine-wide startup item " +
                $"({entry.Source.DisplayName()}). Restart Ballast as administrator to change it.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(entry.Location))
        {
            reason = $"“{entry.DisplayName}” has no recorded location. Rescan startup items and try again.";
            return false;
        }

        if (entry.Source.IsRegistry() && string.IsNullOrEmpty(entry.Name))
        {
            reason = "This registry startup item has no value name, so it cannot be moved safely.";
            return false;
        }

        if (entry.Source.IsRegistry() && StartupBackingStore.Registry(entry.Source) is null)
        {
            reason = $"Ballast does not know how to reach {entry.Source.DisplayName()}.";
            return false;
        }

        if (entry.Source.IsStartupFolder() && StartupBackingStore.Folder(entry.Source) is null)
        {
            reason = $"Ballast could not locate the {entry.Source.DisplayName()} folder.";
            return false;
        }

        reason = null;
        return true;
    }

    private static void ToggleRegistry(StartupEntry entry, bool enable)
    {
        if (StartupBackingStore.Registry(entry.Source) is not { } location)
            throw new InvalidOperationException($"“{entry.DisplayName}” is not a registry startup item.");

        var fromPath = enable ? location.DisabledSubKey : location.RunSubKey;
        var toPath = enable ? location.RunSubKey : location.DisabledSubKey;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(location.Hive, location.View);
            using var from = baseKey.OpenSubKey(fromPath, writable: true);

            object? value = null;
            var kind = RegistryValueKind.Unknown;

            if (from is not null)
            {
                // DoNotExpandEnvironmentNames keeps a REG_EXPAND_SZ command literal, so the
                // value we write back is identical to the one Windows recorded.
                value = from.GetValue(entry.Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

                if (value is not null)
                {
                    try { kind = from.GetValueKind(entry.Name); }
                    catch { kind = RegistryValueKind.Unknown; }
                }
            }

            if (value is null)
            {
                // Nothing to move. If it already sits where the caller wants it, we are done.
                if (ValueExists(baseKey, toPath, entry.Name)) return;

                throw new InvalidOperationException(
                    $"“{entry.Name}” is no longer under {fromPath}. Rescan startup items and try again.");
            }

            using var to = baseKey.CreateSubKey(toPath, writable: true)
                ?? throw new InvalidOperationException($"Could not open {toPath} for writing.");

            to.SetValue(entry.Name, value, kind);
            to.Flush();

            // Copy, verify, and only then remove the original. An entry that exists in both
            // keys is recoverable; a lost command line is not.
            if (to.GetValue(entry.Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is null)
                throw new InvalidOperationException(
                    $"Could not copy “{entry.Name}” to {toPath}; nothing was changed.");

            from!.DeleteValue(entry.Name, throwOnMissingValue: false);
            from.Flush();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new UnauthorizedAccessException(
                $"Windows would not let Ballast change “{entry.DisplayName}” in {fromPath}. " +
                "Restart Ballast as administrator and try again.",
                ex);
        }
    }

    private static bool ValueExists(RegistryKey baseKey, string subKey, string name)
    {
        try
        {
            using var key = baseKey.OpenSubKey(subKey, writable: false);
            return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not null;
        }
        catch
        {
            return false;
        }
    }

    private static void ToggleStartupFolder(StartupEntry entry, bool enable)
    {
        var folder = StartupBackingStore.Folder(entry.Source)
            ?? throw new InvalidOperationException($"Could not locate the {entry.Source.DisplayName()} folder.");

        var disabledFolder = Path.Combine(folder, StartupBackingStore.DisabledFolderName);

        string current;
        try
        {
            current = Path.GetFullPath(entry.Location);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"“{entry.Location}” is not a usable path.", ex);
        }

        var parent = Path.GetDirectoryName(current);

        // Scope guard. We only ever move a file that sits directly in the Startup folder this
        // entry claims, or in our own disabled subfolder of it. A stale or crafted Location
        // cannot make this service touch anything else.
        if (!SamePath(parent, folder) && !SamePath(parent, disabledFolder))
            throw new InvalidOperationException(
                $"Refusing to move “{current}”: it is not inside {folder}.");

        var target = enable ? folder : disabledFolder;

        if (!File.Exists(current))
        {
            // Already moved — by us in an earlier run, or by the user.
            if (File.Exists(Path.Combine(target, Path.GetFileName(current)))) return;

            throw new InvalidOperationException(
                $"“{entry.DisplayName}” is no longer in the {entry.Source.DisplayName()}. " +
                "Rescan startup items and try again.");
        }

        if (SamePath(parent, target)) return;

        try
        {
            Directory.CreateDirectory(target);

            // File.Move without overwrite: a name clash yields a new name, never a lost file.
            File.Move(current, UniqueDestination(target, Path.GetFileName(current)));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new UnauthorizedAccessException(
                $"Windows would not let Ballast move “{Path.GetFileName(current)}”. " +
                "Restart Ballast as administrator and try again.",
                ex);
        }
    }

    private static string UniqueDestination(string folder, string fileName)
    {
        var candidate = Path.Combine(folder, fileName);
        if (!File.Exists(candidate)) return candidate;

        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);

        for (var i = 2; i < 1000; i++)
        {
            candidate = Path.Combine(folder, $"{stem} ({i}){extension}");
            if (!File.Exists(candidate)) return candidate;
        }

        throw new IOException($"Could not find a free name for “{fileName}” in {folder}.");
    }

    private static bool SamePath(string? left, string? right)
    {
        if (string.IsNullOrEmpty(left) || string.IsNullOrEmpty(right)) return false;

        try
        {
            return string.Equals(Trim(left), Trim(right), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }

        static string Trim(string path) =>
            Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static async Task ToggleScheduledTaskAsync(StartupEntry entry, bool enable, CancellationToken ct)
    {
        var taskPath = entry.Location is { Length: > 0 } location ? location : entry.Name;

        // Arguments are passed through ProcessStartInfo.ArgumentList with UseShellExecute off,
        // so there is no shell to inject into; this only rejects names schtasks itself cannot
        // express, which would otherwise fail in a confusing way.
        if (taskPath.Length == 0 || taskPath.AsSpan().IndexOfAny('"', '\r', '\n') >= 0)
            throw new InvalidOperationException(
                $"Refusing to change a scheduled task with an unexpected name: “{taskPath}”.");

        var result = await SchTasks
            .RunAsync(["/change", "/tn", taskPath, enable ? "/enable" : "/disable"], ct)
            .ConfigureAwait(false);

        if (result.ExitCode == 0) return;

        var detail = Describe(result);

        if (LooksLikeAccessDenied(detail))
            throw new UnauthorizedAccessException(
                $"Windows denied the change to the scheduled task “{taskPath}”. " +
                "Restart Ballast as administrator and try again.");

        throw new InvalidOperationException(
            $"schtasks.exe could not {(enable ? "enable" : "disable")} “{taskPath}”: {detail}");
    }

    /// <summary>First meaningful line of a failed schtasks run, capped for display.</summary>
    private static string Describe(SchTasks.Result result)
    {
        var text = string.IsNullOrWhiteSpace(result.StandardError)
            ? result.StandardOutput
            : result.StandardError;

        var line = text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(l => l.Length > 0)
            ?? $"exit code {result.ExitCode}";

        return line.Length <= 300 ? line : line[..300];
    }

    private static bool LooksLikeAccessDenied(string message)
    {
        string[] tokens =
        [
            "denied", "access is denied", "administrator", "privilege", "elevat",
            "verweigert", "refus", "denegado", "negato", "engellendi", "yetki",
        ];

        return tokens.Any(t => message.Contains(t, StringComparison.OrdinalIgnoreCase));
    }
}
