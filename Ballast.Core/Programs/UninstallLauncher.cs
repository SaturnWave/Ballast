using System.ComponentModel;
using System.Diagnostics;
using Ballast.Core.Util;

namespace Ballast.Core.Programs;

/// <summary>
/// An uninstall command line split into the program to run and the arguments to pass it.
/// </summary>
/// <remarks>
/// The two halves are kept apart because <see cref="ProcessStartInfo"/> needs them apart, and
/// because splitting a quoted path on whitespace is the classic bug in this exact place: doing
/// that to <c>"C:\Program Files\App\unins000.exe" /S</c> yields <c>C:\Program</c>, which either
/// fails outright or — much worse — runs something that happens to be sitting there.
/// </remarks>
public readonly record struct UninstallCommandLine(string Executable, string Arguments)
{
    /// <summary>True when there is actually something to run.</summary>
    public bool IsUsable => !string.IsNullOrWhiteSpace(Executable);

    /// <summary>The command as it will be handed to the shell, for logging and for the UI.</summary>
    public override string ToString() =>
        Arguments.Length == 0 ? Executable : $"{Executable} {Arguments}";
}

/// <summary>
/// Starts a program's own uninstaller. That is the entire job.
/// </summary>
/// <remarks>
/// <para>
/// <b>This class never deletes anything.</b> It does not remove files, it does not remove
/// directories, and it does not touch the registry. Deleting an install folder directly is how a
/// machine ends up with half-removed software, orphaned shared components and a registry pointing
/// at nothing, and it is the mistake nearly every "cleaner" makes. The vendor's uninstaller knows
/// which shared components are still needed, which services to stop and what user data it is
/// about to destroy. Ballast's job is to find that uninstaller and get out of the way.
/// </para>
/// <para>
/// The uninstaller's own window appearing is correct behaviour, not a rough edge: those screens
/// are where a person gets warned that saved games, mailboxes or project files are about to go. So
/// nothing here invents a <c>/silent</c> or <c>/quiet</c> flag. A silent run is offered only when
/// the registry itself supplied a <c>QuietUninstallString</c>, and only when the caller explicitly
/// asks for it.
/// </para>
/// <para>
/// <see cref="ProcessStartInfo.UseShellExecute"/> is true so that Windows handles the elevation
/// prompt an all-users uninstaller needs. That also means the outcome is genuinely unknowable from
/// here: <see cref="LaunchAsync"/> reports whether the process <em>started</em>, and the caller
/// must ask the user to rescan rather than claim the program is gone.
/// </para>
/// </remarks>
public sealed class UninstallLauncher
{
    /// <summary>
    /// Extensions that end an unquoted program path. Used only as a fallback when the file cannot
    /// be found on disk, which is common: an uninstaller may already have been removed by a
    /// previous run, leaving a stale registry entry behind.
    /// </summary>
    private static readonly string[] _executableExtensions = [".exe", ".com", ".bat", ".cmd", ".msi"];

    /// <summary>
    /// Wording for the confirmation the UI must show. Kept next to the code that does the work so
    /// the promise and the behaviour cannot drift apart.
    /// </summary>
    public const string SafetyNotice =
        "Ballast does not remove programs itself. It starts the program's own uninstaller, which " +
        "is what knows how to undo the installation. Ballast will not delete any of this " +
        "program's files or registry keys.";

    /// <summary>
    /// Wording for the note shown after a launch. The uninstaller runs outside this process, so
    /// there is no honest way to report that it finished.
    /// </summary>
    public const string RescanHint =
        "The uninstaller is now running on its own. When it finishes, choose Rescan to see " +
        "whether the program is still listed.";

    /// <summary>
    /// Splits a raw uninstall string into an executable and its arguments.
    /// </summary>
    /// <remarks>
    /// Handles the two shapes that actually occur — <c>MsiExec.exe /X{GUID}</c> and
    /// <c>"C:\path\unins000.exe" /flags</c> — plus the awkward third one, an <em>unquoted</em>
    /// path containing spaces. Resolution order:
    /// <list type="number">
    ///   <item>A quoted first token is the executable, full stop.</item>
    ///   <item>Otherwise, try every prefix up to a space, shortest first, and take the first one
    ///         that exists on disk. The filesystem is the only authority on where
    ///         <c>C:\Program Files\App\app.exe --uninstall</c> divides.</item>
    ///   <item>If nothing exists, split after the first prefix ending in an executable extension.
    ///         This is what keeps a stale <c>C:\Program Files\Gone\unins000.exe /S</c> from being
    ///         read as <c>C:\Program</c>.</item>
    ///   <item>Only then fall back to the first whitespace, which is the right answer for a bare
    ///         <c>MsiExec.exe /X{GUID}</c>.</item>
    /// </list>
    /// </remarks>
    public static UninstallCommandLine ParseCommand(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return new UninstallCommandLine(string.Empty, string.Empty);

        string text = commandLine.Trim();

        try
        {
            text = Environment.ExpandEnvironmentVariables(text).Trim();
        }
        catch
        {
            // A malformed %VAR% — keep the literal text and let the shell try.
        }

        if (text.Length == 0) return new UninstallCommandLine(string.Empty, string.Empty);

        // 1. Quoted program. Everything up to the closing quote is the path, however many spaces
        //    it contains; everything after it is arguments.
        if (text[0] is '"')
        {
            int close = text.IndexOf('"', 1);

            string quoted = close > 1 ? text[1..close] : text[1..];
            string rest = close > 0 && close + 1 < text.Length ? text[(close + 1)..] : string.Empty;

            return new UninstallCommandLine(quoted.Trim(), rest.Trim());
        }

        // 2. Unquoted: ask the filesystem where the path ends.
        for (int space = IndexOfSpace(text, 0); space > 0; space = IndexOfSpace(text, space + 1))
        {
            if (Exists(text[..space], out string resolved))
                return new UninstallCommandLine(resolved, text[(space + 1)..].Trim());
        }

        if (Exists(text, out string whole)) return new UninstallCommandLine(whole, string.Empty);

        // 3. Nothing on disk. Trust the extension instead, taking the *longest* match so that
        //    "C:\Program Files\App\unins000.exe /S" is not cut at "C:\Program".
        int extensionSplit = SplitAfterExecutableExtension(text);
        if (extensionSplit > 0)
            return new UninstallCommandLine(text[..extensionSplit].Trim(), text[extensionSplit..].Trim());

        // 4. A bare command name such as "MsiExec.exe /X{GUID}": first whitespace wins, and the
        //    shell resolves the name on PATH.
        int first = IndexOfSpace(text, 0);
        return first > 0
            ? new UninstallCommandLine(text[..first], text[(first + 1)..].Trim())
            : new UninstallCommandLine(text, string.Empty);
    }

    /// <summary>
    /// Starts <paramref name="program"/>'s own uninstaller.
    /// </summary>
    /// <param name="program">The program to uninstall. Nothing about it is modified.</param>
    /// <param name="preferQuiet">
    /// Use the registry's <c>QuietUninstallString</c> when the registry actually provides one.
    /// Ignored otherwise — no silent flag is ever synthesised.
    /// </param>
    /// <param name="ct">Cancels the launch attempt only. Once the uninstaller is running it is
    /// out of our hands.</param>
    /// <returns>
    /// True when the process started. <b>Not</b> whether the uninstall succeeded: that finishes
    /// outside this process, so the caller must ask the user to rescan.
    /// </returns>
    public async Task<bool> LaunchAsync(
        InstalledProgram program,
        bool preferQuiet = false,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(program);

        bool quiet = preferQuiet && program.HasQuietUninstall;
        string? raw = quiet ? program.QuietUninstallCommand : program.UninstallCommand;

        // Fall back to whichever one exists rather than refusing: some installers register only a
        // quiet string, and an interactive request should still be able to run something.
        raw = string.IsNullOrWhiteSpace(raw)
            ? program.UninstallCommand ?? program.QuietUninstallCommand
            : raw;

        if (string.IsNullOrWhiteSpace(raw))
        {
            ActionLog.Info(
                $"No uninstaller is registered for '{program.DisplayName}' ({program.RegistryKeyPath}). " +
                "Nothing was launched and nothing was removed.");
            return false;
        }

        UninstallCommandLine line = ParseCommand(raw);

        if (!line.IsUsable)
        {
            ActionLog.Failed(
                program.RegistryKeyPath,
                $"the uninstall command for '{program.DisplayName}' could not be parsed: {raw}");
            return false;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = line.Executable,
            Arguments = line.Arguments,

            // The shell, so Windows shows the elevation prompt an all-users uninstaller needs and
            // resolves bare names such as MsiExec.exe on PATH. It also means we cannot redirect or
            // watch the child, which is fine: this method only reports that it started.
            UseShellExecute = true,
        };

        // Several older uninstallers read files relative to their own folder.
        if (WorkingDirectoryFor(line.Executable) is { } workingDirectory)
            startInfo.WorkingDirectory = workingDirectory;

        try
        {
            // ShellExecute blocks while the elevation prompt is on screen, so keep it off the
            // caller's thread.
            using Process? process = await Task.Run(() => Process.Start(startInfo), ct).ConfigureAwait(false);

            ActionLog.Info(
                $"Launched the vendor uninstaller for '{program.DisplayName}' " +
                $"({(quiet ? "the registry's quiet command" : "interactive")}): {line}. " +
                "Ballast removed nothing itself.");

            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Win32Exception ex)
        {
            // 1223 is ERROR_CANCELLED: the user dismissed the elevation prompt. That is a normal
            // answer, not a fault, and nothing has happened to the machine.
            string reason = ex.NativeErrorCode == 1223
                ? "the elevation prompt was dismissed, so nothing was uninstalled"
                : $"the uninstaller could not be started ({ex.Message})";

            ActionLog.Failed(line.Executable, $"'{program.DisplayName}': {reason}");
            return false;
        }
        catch (Exception ex)
        {
            ActionLog.Failed(
                line.Executable,
                $"'{program.DisplayName}': the uninstaller could not be started ({ex.Message})");
            return false;
        }
    }

    /// <summary>
    /// Reports install folders that still exist. Purely informational: Ballast does not delete
    /// them, and the UI must say so. What looks like a leftover is very often a folder holding
    /// the user's own documents, licences or save files, and a shared component another program
    /// is still using looks exactly the same from out here.
    /// </summary>
    public static IReadOnlyList<string> FindRemainingFolders(IEnumerable<InstalledProgram> programs)
    {
        ArgumentNullException.ThrowIfNull(programs);

        List<string> remaining = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (InstalledProgram program in programs)
        {
            if (program?.InstallLocation is not { Length: > 0 } location) continue;

            string trimmed = location.Trim().Trim('"');
            if (trimmed.Length == 0 || !seen.Add(trimmed)) continue;

            try
            {
                if (Directory.Exists(trimmed)) remaining.Add(trimmed);
            }
            catch
            {
                // An unreadable or malformed path is simply not reported.
            }
        }

        return remaining;
    }

    /// <summary>The executable's own folder, when it is a real path that exists.</summary>
    private static string? WorkingDirectoryFor(string executable)
    {
        try
        {
            if (!Path.IsPathFullyQualified(executable)) return null;

            string? folder = Path.GetDirectoryName(executable);
            return folder is { Length: > 0 } && Directory.Exists(folder) ? folder : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Index of the next space or tab at or after <paramref name="from"/>, else -1.</summary>
    private static int IndexOfSpace(string text, int from)
    {
        for (int i = Math.Max(from, 0); i < text.Length; i++)
        {
            if (text[i] is ' ' or '\t') return i;
        }

        return -1;
    }

    /// <summary>
    /// True when <paramref name="candidate"/> names a file that exists, tolerating surrounding
    /// quotes and a missing <c>.exe</c>.
    /// </summary>
    private static bool Exists(string candidate, out string resolved)
    {
        resolved = string.Empty;

        string cleaned = candidate.Trim().Trim('"');
        if (cleaned.Length == 0) return false;

        try
        {
            if (File.Exists(cleaned))
            {
                resolved = cleaned;
                return true;
            }

            if (!Path.HasExtension(cleaned) && File.Exists(cleaned + ".exe"))
            {
                resolved = cleaned + ".exe";
                return true;
            }
        }
        catch
        {
            // Illegal characters, an unavailable drive: treat as not found.
        }

        return false;
    }

    /// <summary>
    /// Index of the whitespace that follows the <em>first</em> executable extension, or -1.
    /// </summary>
    /// <remarks>
    /// First rather than last, because an argument is often itself a path to an executable
    /// (<c>setup.exe --uninstall C:\other\thing.exe</c>) and matching the rightmost one would
    /// treat the whole command as the program name. The reverse mistake — a directory genuinely
    /// called "Setup.exe stuff" — needs no handling here, because a path that exists on disk has
    /// already been resolved by the filesystem probe before this fallback is reached.
    /// </remarks>
    private static int SplitAfterExecutableExtension(string text)
    {
        for (int space = IndexOfSpace(text, 0); space > 0; space = IndexOfSpace(text, space + 1))
        {
            string prefix = text[..space];

            foreach (string extension in _executableExtensions)
            {
                if (prefix.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return space;
            }
        }

        return -1;
    }
}
