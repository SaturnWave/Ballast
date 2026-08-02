using System.Globalization;
using Microsoft.Win32;

namespace Ballast.Core.Programs;

/// <summary>
/// The raw values one uninstall subkey can carry, before any interpretation. Exists so the
/// "should this row be listed at all?" decision in <see cref="InstalledProgramScanner.ShouldHide"/>
/// is a pure function of registry data and can be tested without a registry.
/// </summary>
public sealed record UninstallKeyValues
{
    /// <summary>The <c>DisplayName</c> value.</summary>
    public string? DisplayName { get; init; }

    /// <summary>The <c>UninstallString</c> value.</summary>
    public string? UninstallString { get; init; }

    /// <summary>The <c>ReleaseType</c> value, e.g. <c>Update</c> or <c>Security Update</c>.</summary>
    public string? ReleaseType { get; init; }

    /// <summary>The <c>ParentKeyName</c> value: set when this row belongs to another product.</summary>
    public string? ParentKeyName { get; init; }

    /// <summary>The <c>SystemComponent</c> DWORD. 1 means "do not list me".</summary>
    public int? SystemComponent { get; init; }

    /// <summary>The <c>WindowsInstaller</c> DWORD. 1 means the row is owned by Windows Installer.</summary>
    public int? WindowsInstaller { get; init; }
}

/// <summary>
/// Read-only enumeration of the Windows uninstall registry — the same three keys Add or Remove
/// Programs reads.
/// </summary>
/// <remarks>
/// <para>
/// This class only ever reads. It never writes a value, never deletes a key, and never touches a
/// program's files: removing software is the vendor uninstaller's job, started by
/// <see cref="UninstallLauncher"/>.
/// </para>
/// <para>
/// Every hive, key and value access is individually guarded. One locked or malformed entry
/// degrades to "that row is missing", never to a failed scan — a machine with one broken
/// uninstall key must still get a usable list.
/// </para>
/// </remarks>
public sealed class InstalledProgramScanner
{
    private const string UninstallSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallSubKeyWow = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>
    /// Joins the parts of a de-duplication key. A control character, so a display name that
    /// happens to contain the separator cannot collide with a different product.
    /// </summary>
    private const char IdentitySeparator = '\u001f';

    /// <summary>
    /// A byte total above this is treated as "not recorded" rather than shown. Nothing a person
    /// installs is a terabyte, and a handful of installers leave <c>0xFFFFFFFF</c> in
    /// <c>EstimatedSize</c>, which would otherwise be reported as a straight-faced 4.4 TB.
    /// </summary>
    public const long ImplausibleProgramSizeBytes = 1_000L * 1_000 * 1_000 * 1_000;

    /// <summary>
    /// <c>ReleaseType</c> values that mark an update to a product rather than a product. Windows
    /// lists these under Installed Updates.
    /// </summary>
    private static readonly HashSet<string> _updateReleaseTypes =
        new(StringComparer.OrdinalIgnoreCase) { "Update", "Hotfix", "Security Update" };

    /// <summary>Label for the UI, matching the shape of the other scanners.</summary>
    public string Name => "Installed Programs";

    /// <summary>
    /// Reads all three uninstall registries on a background thread, drops the rows Add or Remove
    /// Programs itself hides, de-duplicates and orders by name.
    /// </summary>
    public Task<IReadOnlyList<InstalledProgram>> ScanAsync(CancellationToken ct = default) =>
        Task.Run(() => Scan(ct), ct);

    /// <summary>
    /// Decides whether a row should be listed, mirroring what Add or Remove Programs hides.
    /// <paramref name="reason"/> is a plain-English explanation when the answer is true.
    /// </summary>
    public static bool ShouldHide(UninstallKeyValues values, out string? reason)
    {
        ArgumentNullException.ThrowIfNull(values);

        reason = null;

        // 1. No name at all. Add or Remove Programs has nothing to draw, and neither do we. These
        //    rows are usually Windows Installer bookkeeping or an installer that died halfway.
        string? name = values.DisplayName?.Trim();
        if (string.IsNullOrEmpty(name))
        {
            reason = "the entry has no DisplayName";
            return true;
        }

        // 2. "KB" followed by a digit is a Windows hotfix. Windows lists those under Installed
        //    Updates rather than under programs. The digit test is the point of the rule: it keeps
        //    real products whose names merely begin with those letters ("KBase Editor") in the list.
        if (name.Length > 2
            && name.StartsWith("KB", StringComparison.OrdinalIgnoreCase)
            && char.IsAsciiDigit(name[2]))
        {
            reason = "the name looks like a Windows hotfix (KB followed by digits)";
            return true;
        }

        // 3. SystemComponent = 1 is the vendor explicitly asking not to be listed. Runtimes and
        //    redistributables use it, and pulling one out from under the applications that depend
        //    on it is exactly the kind of damage this page must not invite.
        if (values.SystemComponent == 1)
        {
            reason = "the entry is flagged SystemComponent";
            return true;
        }

        // 4. An update, hotfix or security update to a product, not the product itself.
        if (values.ReleaseType is { Length: > 0 } releaseType && _updateReleaseTypes.Contains(releaseType.Trim()))
        {
            reason = $"the entry is a {releaseType.Trim()} rather than a program";
            return true;
        }

        // 5. ParentKeyName means the row belongs to another product (a language pack, a bundled
        //    component). Removing it on its own leaves the parent half-installed.
        if (!string.IsNullOrWhiteSpace(values.ParentKeyName))
        {
            reason = "the entry belongs to another product (ParentKeyName is set)";
            return true;
        }

        // 6. A Windows Installer row with no UninstallString is an installer record with nothing
        //    to run — a patch or a component, not something a person chose to install.
        if (values.WindowsInstaller == 1 && string.IsNullOrWhiteSpace(values.UninstallString))
        {
            reason = "a Windows Installer entry with no UninstallString";
            return true;
        }

        return false;
    }

    /// <summary>
    /// Converts a raw <c>EstimatedSize</c> value to bytes. The registry stores it as a DWORD in
    /// <b>kilobytes</b>, so the value is multiplied by 1024.
    /// </summary>
    /// <remarks>
    /// Returns null — not zero — when the size is missing, zero or implausible. Most programs
    /// record no size at all, and "0 KB" next to a 4 GB application is not a rounding error, it is
    /// the list telling the user something false.
    /// </remarks>
    public static long? EstimatedSizeToBytes(object? registryValue)
    {
        long kilobytes;

        switch (registryValue)
        {
            case null:
                return null;

            // A REG_DWORD arrives as int. Anything above 2^31 comes back negative, so reinterpret
            // the bit pattern as unsigned instead of reading a nonsensical negative size.
            case int i:
                kilobytes = unchecked((uint)i);
                break;

            case uint u:
                kilobytes = u;
                break;

            case long l:
                kilobytes = l;
                break;

            // A few installers write the number as a string.
            case string s when long.TryParse(
                s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed):
                kilobytes = parsed;
                break;

            default:
                return null;
        }

        // 0 means "not recorded". Treating it as a real measurement is the specific bug this
        // method exists to prevent.
        if (kilobytes <= 0) return null;

        // Compared before multiplying, so a garbage value cannot overflow the multiplication.
        if (kilobytes >= ImplausibleProgramSizeBytes / 1024) return null;

        return kilobytes * 1024L;
    }

    /// <summary>
    /// Parses a raw <c>InstallDate</c> value. The documented form is <c>yyyyMMdd</c>; a locale
    /// date string and a numeric DWORD both turn up in practice, so both are accepted. Anything
    /// unparseable or outside 1990-2099 is null rather than a guess.
    /// </summary>
    public static DateOnly? ParseInstallDate(object? registryValue)
    {
        string? text = registryValue switch
        {
            null => null,
            string s => s.Trim(),
            int i => i.ToString(CultureInfo.InvariantCulture),
            long l => l.ToString(CultureInfo.InvariantCulture),
            _ => registryValue.ToString()?.Trim(),
        };

        if (string.IsNullOrWhiteSpace(text)) return null;

        if (DateOnly.TryParseExact(
                text, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly exact))
            return Plausible(exact);

        if (DateOnly.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.None, out DateOnly current))
            return Plausible(current);

        if (DateOnly.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly invariant))
            return Plausible(invariant);

        return null;

        // A parse can succeed and still be junk: "00010101" and similar sentinels are common.
        static DateOnly? Plausible(DateOnly date) => date.Year is >= 1990 and <= 2099 ? date : null;
    }

    /// <summary>
    /// Collapses rows describing the same product, then orders by name.
    /// </summary>
    /// <remarks>
    /// A product routinely appears in more than one of the three registries — most often in both
    /// the 32-bit and 64-bit views of HKLM, where a 64-bit installer registered a 32-bit
    /// component under the same key name. Two rows are treated as the same product when both the
    /// subkey name (the product code, for MSI installs) and the display name match.
    /// </remarks>
    public static IReadOnlyList<InstalledProgram> Deduplicate(IEnumerable<InstalledProgram> programs)
    {
        ArgumentNullException.ThrowIfNull(programs);

        List<InstalledProgram> kept = [];
        Dictionary<string, int> positions = new(StringComparer.OrdinalIgnoreCase);

        foreach (InstalledProgram program in programs)
        {
            if (program is null) continue;

            string identity = string.Join(IdentitySeparator, program.KeyName.Trim(), program.DisplayName.Trim());

            if (!positions.TryGetValue(identity, out int at))
            {
                positions[identity] = kept.Count;
                kept.Add(program);
                continue;
            }

            if (IsBetter(program, kept[at])) kept[at] = program;
        }

        return [.. kept.OrderBy(p => p.DisplayName, StringComparer.CurrentCultureIgnoreCase)];
    }

    /// <summary>
    /// Picks between two rows for the same product. The rule that matters: an entry that can
    /// actually be uninstalled beats one that cannot, so a stub row never leaves the Uninstall
    /// button dead when a working registration exists. Failing that, an entry that knows its size
    /// beats one that does not, and a complete tie keeps whichever was read first.
    /// </summary>
    private static bool IsBetter(InstalledProgram candidate, InstalledProgram incumbent)
    {
        if (candidate.CanUninstall != incumbent.CanUninstall) return candidate.CanUninstall;

        bool candidateKnowsSize = candidate.EstimatedSizeBytes is not null;
        if (candidateKnowsSize != (incumbent.EstimatedSizeBytes is not null)) return candidateKnowsSize;

        return false;
    }

    private static IReadOnlyList<InstalledProgram> Scan(CancellationToken ct)
    {
        List<InstalledProgram> found = [];

        foreach (UninstallRegistry source in Sources())
        {
            ct.ThrowIfCancellationRequested();
            Read(source, found, ct);
        }

        return Deduplicate(found);
    }

    private static IEnumerable<UninstallRegistry> Sources()
    {
        // Machine-wide, native view.
        yield return new UninstallRegistry(
            RegistryHive.LocalMachine, RegistryView.Registry64, UninstallSubKey,
            ProgramScope.AllUsers, @"HKLM\" + UninstallSubKey);

        // The Registry32 view of the same relative path *is* WOW6432Node, which is why the
        // redirected path is carried separately for display. On a 32-bit OS the two views are the
        // same key, so reading it twice would only manufacture duplicates.
        if (Environment.Is64BitOperatingSystem)
        {
            yield return new UninstallRegistry(
                RegistryHive.LocalMachine, RegistryView.Registry32, UninstallSubKey,
                ProgramScope.AllUsers32Bit, @"HKLM\" + UninstallSubKeyWow);
        }

        // Per-user installs. Read once, with the default view: registry redirection covers
        // HKLM\Software and HKCU\Software\Classes, but not HKCU\Software itself, so 32-bit and
        // 64-bit installers write per-user entries to the very same key.
        yield return new UninstallRegistry(
            RegistryHive.CurrentUser, RegistryView.Default, UninstallSubKey,
            ProgramScope.CurrentUser, @"HKCU\" + UninstallSubKey);
    }

    private static void Read(UninstallRegistry source, List<InstalledProgram> into, CancellationToken ct)
    {
        RegistryKey baseKey;
        try
        {
            baseKey = RegistryKey.OpenBaseKey(source.Hive, source.View);
        }
        catch
        {
            // Hive unavailable (locked down, roaming profile). That source is simply empty.
            return;
        }

        using (baseKey)
        {
            RegistryKey? uninstall;
            try
            {
                uninstall = baseKey.OpenSubKey(source.SubKey, writable: false);
            }
            catch
            {
                return;
            }

            if (uninstall is null) return;

            using (uninstall)
            {
                string[] names;
                try
                {
                    names = uninstall.GetSubKeyNames();
                }
                catch
                {
                    return;
                }

                foreach (string name in names)
                {
                    ct.ThrowIfCancellationRequested();

                    if (string.IsNullOrEmpty(name)) continue;

                    try
                    {
                        if (ReadEntry(uninstall, name, source) is { } program) into.Add(program);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        // One unreadable or malformed entry must not cost us the whole list.
                    }
                }
            }
        }
    }

    private static InstalledProgram? ReadEntry(RegistryKey uninstall, string subKeyName, UninstallRegistry source)
    {
        using RegistryKey? key = uninstall.OpenSubKey(subKeyName, writable: false);
        if (key is null) return null;

        var values = new UninstallKeyValues
        {
            DisplayName = ReadString(key, "DisplayName"),
            UninstallString = ReadString(key, "UninstallString"),
            ReleaseType = ReadString(key, "ReleaseType"),
            ParentKeyName = ReadString(key, "ParentKeyName"),
            SystemComponent = ReadFlag(key, "SystemComponent"),
            WindowsInstaller = ReadFlag(key, "WindowsInstaller"),
        };

        if (ShouldHide(values, out _)) return null;

        // ShouldHide already rejected a blank name; this is belt and braces so the required
        // property below is never assigned an empty string.
        string displayName = values.DisplayName?.Trim() ?? string.Empty;
        if (displayName.Length == 0) return null;

        string? quiet = ReadString(key, "QuietUninstallString");

        return new InstalledProgram
        {
            DisplayName = displayName,
            Publisher = ReadString(key, "Publisher"),
            Version = ReadString(key, "DisplayVersion"),
            InstallDate = ParseInstallDate(ReadValue(key, "InstallDate")),
            EstimatedSizeBytes = EstimatedSizeToBytes(ReadValue(key, "EstimatedSize")),
            InstallLocation = ReadString(key, "InstallLocation"),
            UninstallCommand = values.UninstallString,
            QuietUninstallCommand = quiet,
            IconPath = ReadString(key, "DisplayIcon"),
            RegistryKeyPath = $@"{source.DisplayRoot}\{subKeyName}",
            Scope = source.Scope,
            IsMsi = values.WindowsInstaller == 1
                || LooksLikeMsiExec(values.UninstallString)
                || LooksLikeMsiExec(quiet),
        };
    }

    /// <summary>True when a command line runs msiexec, whatever path or casing it uses.</summary>
    private static bool LooksLikeMsiExec(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;

        UninstallCommandLine line = UninstallLauncher.ParseCommand(command);
        if (line.Executable.Length == 0) return false;

        try
        {
            return Path.GetFileNameWithoutExtension(line.Executable)
                .Equals("msiexec", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // Illegal characters in the path: not something we can call msiexec.
            return false;
        }
    }

    /// <summary>Raw value read, guarded. Null when the value is absent or unreadable.</summary>
    private static object? ReadValue(RegistryKey key, string name)
    {
        try
        {
            return key.GetValue(name);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Trimmed string value, or null when absent or blank. Environment variables are deliberately
    /// left expanded (the default): an uninstall string containing <c>%ProgramFiles%</c> has to be
    /// runnable, unlike the startup values that must round-trip byte for byte.
    /// </summary>
    private static string? ReadString(RegistryKey key, string name)
    {
        string? text = ReadValue(key, name)?.ToString()?.Trim();
        return string.IsNullOrEmpty(text) ? null : text;
    }

    /// <summary>A 0/1 DWORD, tolerating the installers that write it as a string.</summary>
    private static int? ReadFlag(RegistryKey key, string name) => ReadValue(key, name) switch
    {
        int i => i,
        long l => l is >= int.MinValue and <= int.MaxValue ? (int)l : null,
        string s when int.TryParse(
            s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) => parsed,
        _ => null,
    };

    /// <summary>One of the three uninstall registries, and how to describe it.</summary>
    private readonly record struct UninstallRegistry(
        RegistryHive Hive,
        RegistryView View,
        string SubKey,
        ProgramScope Scope,
        string DisplayRoot);
}
