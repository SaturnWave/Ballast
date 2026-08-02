using System.Diagnostics;
using Microsoft.Win32;

namespace Ballast.Core.Startup;

/// <summary>
/// Where an auto-start entry physically lives. This decides how the entry is toggled,
/// so it must round-trip exactly: never infer it from a display string.
/// </summary>
public enum StartupSource
{
    /// <summary>HKCU\Software\Microsoft\Windows\CurrentVersion\Run — this user only.</summary>
    RegistryRunHkcu,

    /// <summary>HKLM\Software\Microsoft\Windows\CurrentVersion\Run — every user, needs admin.</summary>
    RegistryRunHklm,

    /// <summary>The 32-bit (WOW6432Node) view of the machine Run key, needs admin.</summary>
    RegistryRunHklmWow64,

    /// <summary>The current user's Startup folder.</summary>
    StartupFolderUser,

    /// <summary>The all-users Startup folder in ProgramData, needs admin.</summary>
    StartupFolderCommon,

    /// <summary>A Task Scheduler task with a logon trigger.</summary>
    ScheduledTask,
}

/// <summary>Presentation and capability facts about a <see cref="StartupSource"/>.</summary>
public static class StartupSourceInfo
{
    public static string DisplayName(this StartupSource s) => s switch
    {
        StartupSource.RegistryRunHkcu      => "For you",
        StartupSource.RegistryRunHklm      => "All users",
        StartupSource.RegistryRunHklmWow64 => "All users (32-bit)",
        StartupSource.StartupFolderUser    => "Startup folder",
        StartupSource.StartupFolderCommon  => "Startup folder (all users)",
        StartupSource.ScheduledTask        => "Scheduled task",
        _ => s.ToString(),
    };

    public static string Description(this StartupSource s) => s switch
    {
        StartupSource.RegistryRunHkcu      => "Launches when you sign in. Only affects your account.",
        StartupSource.RegistryRunHklm      => "Launches for everyone who signs in to this PC. Requires administrator rights.",
        StartupSource.RegistryRunHklmWow64 => "A 32-bit app registered to launch for everyone. Requires administrator rights.",
        StartupSource.StartupFolderUser    => "A shortcut in your Startup folder.",
        StartupSource.StartupFolderCommon  => "A shortcut in the shared Startup folder. Requires administrator rights.",
        StartupSource.ScheduledTask        => "A scheduled task that runs when you sign in. Usually requires administrator rights.",
        _ => string.Empty,
    };

    /// <summary>Glyph from the Segoe Fluent Icons font.</summary>
    public static string Glyph(this StartupSource s) => s switch
    {
        StartupSource.RegistryRunHkcu      => "\uE77B",
        StartupSource.RegistryRunHklm      => "\uE716",
        StartupSource.RegistryRunHklmWow64 => "\uE716",
        StartupSource.StartupFolderUser    => "\uE8B7",
        StartupSource.StartupFolderCommon  => "\uE8B7",
        StartupSource.ScheduledTask        => "\uE823",
        _ => "\uE7C3",
    };

    /// <summary>True when changing this entry writes to a machine-wide store.</summary>
    public static bool RequiresAdmin(this StartupSource s) => s is
        StartupSource.RegistryRunHklm or
        StartupSource.RegistryRunHklmWow64 or
        StartupSource.StartupFolderCommon or
        StartupSource.ScheduledTask;

    public static bool IsRegistry(this StartupSource s) => s is
        StartupSource.RegistryRunHkcu or
        StartupSource.RegistryRunHklm or
        StartupSource.RegistryRunHklmWow64;

    public static bool IsStartupFolder(this StartupSource s) => s is
        StartupSource.StartupFolderUser or
        StartupSource.StartupFolderCommon;
}

/// <summary>
/// The exact registry key a <see cref="StartupSource"/> maps to. <c>RunSubKey</c> is opened
/// relative to <c>Hive</c> under <c>View</c>; the 32-bit view resolves to WOW6432Node without
/// us naming it, which is why the redirected path is carried separately as <c>DisplayPath</c>
/// for display and round-tripping.
/// </summary>
internal readonly record struct StartupRegistryLocation(
    RegistryHive Hive,
    RegistryView View,
    string RunSubKey,
    string DisabledSubKey,
    string DisplayPath);

/// <summary>
/// Single source of truth for the stores the scanner reads and the toggle service writes.
/// Disabling is implemented as a <em>move</em> into a parallel store owned by this app,
/// so an entry can always be put back byte-for-byte.
/// </summary>
internal static class StartupBackingStore
{
    /// <summary>Appended to a Run key name to hold values we disabled.</summary>
    internal const string DisabledKeySuffix = "-disabled-Ballast";

    /// <summary>Subfolder of a Startup folder that holds shortcuts we disabled.</summary>
    internal const string DisabledFolderName = "Disabled-Ballast";

    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunPathWow = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";

    internal static StartupRegistryLocation? Registry(StartupSource source) => source switch
    {
        StartupSource.RegistryRunHkcu => new StartupRegistryLocation(
            RegistryHive.CurrentUser, RegistryView.Registry64,
            RunPath, RunPath + DisabledKeySuffix, @"HKCU\" + RunPath),

        StartupSource.RegistryRunHklm => new StartupRegistryLocation(
            RegistryHive.LocalMachine, RegistryView.Registry64,
            RunPath, RunPath + DisabledKeySuffix, @"HKLM\" + RunPath),

        // Registry32 view of the same relative path *is* WOW6432Node on a 64-bit OS.
        StartupSource.RegistryRunHklmWow64 => new StartupRegistryLocation(
            RegistryHive.LocalMachine, RegistryView.Registry32,
            RunPath, RunPath + DisabledKeySuffix, @"HKLM\" + RunPathWow),

        _ => null,
    };

    /// <summary>The Startup folder backing a folder-based source, or null for other sources.</summary>
    internal static string? Folder(StartupSource source)
    {
        Environment.SpecialFolder? special = source switch
        {
            StartupSource.StartupFolderUser   => Environment.SpecialFolder.Startup,
            StartupSource.StartupFolderCommon => Environment.SpecialFolder.CommonStartup,
            _ => null,
        };

        if (special is null) return null;

        try
        {
            var path = Environment.GetFolderPath(special.Value);
            return string.IsNullOrWhiteSpace(path) ? null : path;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// One thing that launches at sign-in. Produced by <see cref="StartupScanner"/>; purely
/// descriptive — nothing on this type changes system state.
/// </summary>
public sealed class StartupEntry
{
    /// <summary>
    /// Registry value name, shortcut file name without extension, or the task's leaf name.
    /// For registry sources this is the key the toggle service reads and writes, so it is
    /// stored verbatim.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>The raw command line as recorded by Windows, arguments and all.</summary>
    public required string Command { get; init; }

    /// <summary>
    /// The executable teased out of <see cref="Command"/> (quotes and arguments stripped),
    /// resolved to a full path when the file could be found on disk. Null when the command
    /// is not a resolvable local program (a URL, a COM handler, a deleted app).
    /// </summary>
    public string? ExecutablePath { get; init; }

    /// <summary>
    /// <see cref="FileVersionInfo.CompanyName"/> of <see cref="ExecutablePath"/>.
    /// Null when the executable does not resolve or carries no version resource — an
    /// unsigned, publisher-less entry is exactly what a user wants to notice.
    /// </summary>
    public string? Publisher { get; init; }

    public required StartupSource Source { get; init; }

    /// <summary>False when the entry is parked in this app's disabled store, or a task is disabled.</summary>
    public bool IsEnabled { get; init; }

    /// <summary>True when toggling this entry needs an elevated process.</summary>
    public bool RequiresAdmin { get; init; }

    /// <summary>
    /// The exact store this entry was read from, for round-tripping: the full registry key
    /// path (including the disabled suffix when disabled), the full path of the shortcut file
    /// as it sits right now, or the full scheduled-task path such as <c>\MyApp\Updater</c>.
    /// </summary>
    public required string Location { get; init; }

    public string DisplayName =>
        Name is { Length: > 0 } n ? n
        : ExecutablePath is { Length: > 0 } e ? Path.GetFileName(e)
        : Command;

    /// <summary>Secondary line for the UI: who made it, else what it runs.</summary>
    public string Detail => Publisher ?? ExecutablePath ?? Command;

    /// <summary>
    /// Builds an entry, parsing the executable out of <paramref name="command"/> and reading
    /// its publisher. Pass <paramref name="executablePath"/> when the caller already resolved
    /// it (a shortcut target, say) to skip the guesswork.
    /// </summary>
    public static StartupEntry Create(
        string name,
        string command,
        StartupSource source,
        string location,
        bool isEnabled,
        string? executablePath = null,
        bool? requiresAdmin = null)
    {
        var exe = executablePath is { Length: > 0 }
            ? ResolveIfPossible(executablePath)
            : ParseExecutablePath(command);

        return new StartupEntry
        {
            Name = name ?? string.Empty,
            Command = command ?? string.Empty,
            ExecutablePath = exe,
            Publisher = ReadPublisher(exe),
            Source = source,
            Location = location ?? string.Empty,
            IsEnabled = isEnabled,
            RequiresAdmin = requiresAdmin ?? source.RequiresAdmin(),
        };
    }

    /// <summary>
    /// Extracts the program from a raw command line. Handles the quoted form, the unquoted
    /// form with spaces in the path (<c>C:\Program Files\App\app.exe --silent</c>), missing
    /// extensions, and environment variables. Returns a full path when the file exists,
    /// otherwise the best-guess first token, and null when nothing usable is there.
    /// </summary>
    public static string? ParseExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;

        var text = command.Trim();
        try { text = Environment.ExpandEnvironmentVariables(text).Trim(); }
        catch { /* malformed %VAR% — keep the literal text */ }

        if (text.Length == 0) return null;

        // Quoted program: "C:\Program Files\App\app.exe" --flag
        if (text[0] is '"' or '\'')
        {
            var quote = text[0];
            var close = text.IndexOf(quote, 1);
            var inner = close > 1 ? text[1..close] : text[1..];

            if (TryResolveFile(inner, out var quotedFull)) return quotedFull;

            var quotedGuess = Clean(inner);
            return quotedGuess.Length == 0 ? null : quotedGuess;
        }

        // Unquoted: walk the spaces shortest-prefix-first, because both
        // "C:\Windows\notepad.exe file.txt" and "C:\Program Files\App\app.exe -q" are legal.
        for (var i = text.IndexOf(' '); i >= 0; i = text.IndexOf(' ', i + 1))
        {
            if (TryResolveFile(text[..i], out var full)) return full;
        }

        if (TryResolveFile(text, out var whole)) return whole;

        var token = Clean(text.Split(' ', 2)[0]);
        return token.Length == 0 ? null : token;
    }

    /// <summary>Reads the company name off an executable. Never throws.</summary>
    public static string? ReadPublisher(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath)) return null;

        try
        {
            if (!File.Exists(executablePath)) return null;
            var company = FileVersionInfo.GetVersionInfo(executablePath).CompanyName?.Trim();
            return string.IsNullOrEmpty(company) ? null : company;
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveIfPossible(string candidate) =>
        TryResolveFile(candidate, out var full) ? full : Clean(candidate) is { Length: > 0 } c ? c : null;

    private static bool TryResolveFile(string candidate, out string resolved)
    {
        resolved = string.Empty;
        var cleaned = Clean(candidate);
        if (cleaned.Length == 0) return false;

        try
        {
            if (File.Exists(cleaned))
            {
                resolved = Path.GetFullPath(cleaned);
                return true;
            }

            // Run keys frequently omit the extension.
            if (!Path.HasExtension(cleaned) && File.Exists(cleaned + ".exe"))
            {
                resolved = Path.GetFullPath(cleaned + ".exe");
                return true;
            }
        }
        catch
        {
            // Illegal characters, an unavailable drive — treat as unresolvable.
        }

        return false;
    }

    /// <summary>Trims the punctuation that clings to paths in Run values (quotes, trailing commas).</summary>
    private static string Clean(string value) =>
        value.Trim().Trim('"', '\'').TrimEnd(',', ' ').Trim();
}
