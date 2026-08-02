namespace Ballast.Core.Security.Rules;

/// <summary>
/// Files that borrow the name of a Windows system program while living somewhere Windows does
/// not keep its own programs.
/// </summary>
public sealed class SystemBinaryMasqueradeRule : ISecurityRule
{
    /// <summary>
    /// Names of Windows processes that a person might see in Task Manager and accept without
    /// question. The list is deliberately short: every name on it ships only with Windows, so a
    /// copy outside the Windows folder has no ordinary explanation. Names that third parties also
    /// legitimately use are not on it, and adding one to catch more would cost more than it wins.
    /// </summary>
    private static readonly HashSet<string> SystemProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "explorer.exe",
        "rundll32.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "dwm.exe", "taskhostw.exe",
        "ctfmon.exe", "sihost.exe", "conhost.exe", "dllhost.exe", "lsaiso.exe", "searchindexer.exe",
    };

    public string RuleId => "BAL-MASQUERADE";

    public string Name => "Files impersonating Windows system programs";

    public string Rationale =>
        "Windows keeps svchost.exe, lsass.exe and their siblings inside the Windows folder. A file " +
        "with one of those names anywhere else is not that Windows program — it is something else " +
        "wearing the name, and the reason to wear it is that people who check Task Manager " +
        "recognise the name and move on. This is a long-established impersonation technique and " +
        "there is almost no innocent reason for such a copy to exist, which is why it is High.\n\n" +
        "Deliberately NOT flagged: anything under the Windows folder, which includes WinSxS and " +
        "Windows.old — both hold genuine copies of these files, and a machine that has taken a " +
        "feature update is full of them. Anything whose location cannot be determined, such as a " +
        "bare command name resolved through PATH, is also left alone: the rule is about where a " +
        "file lives, so if that is unknown the rule has nothing to say. The one exception to the " +
        "Windows-folder pass is a Temp folder inside it — C:\\Windows\\Temp is scratch space, not a " +
        "place Windows keeps its own programs.";

    public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<SecurityFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in ContextPaths.Executables(context))
        {
            ct.ThrowIfCancellationRequested();

            var fileName = SafeFileName(candidate.Path);
            if (fileName.Length == 0 || !SystemProcessNames.Contains(fileName)) continue;

            // Under %WINDIR% it is almost certainly the real thing — unless it is sitting in
            // scratch space, where Windows never puts its own programs.
            if (PathFacts.IsUnderWindowsFolder(candidate.Path) && !PathFacts.IsTempLike(candidate.Path)) continue;

            if (!seen.Add(candidate.Path)) continue;

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = $"A file named {fileName} is outside the Windows folder",
                Severity = FindingSeverity.High,
                Explanation =
                    $"Windows keeps {fileName} inside the Windows folder and runs it from there. " +
                    "The file below has the same name but lives somewhere else, so it is not that " +
                    "Windows program — it is a different file using a familiar name. Reusing a " +
                    "system process name is a recognised way of looking ordinary in Task Manager, " +
                    "and legitimate software has no reason to do it.",
                Evidence = $"{candidate.Path} — {candidate.Origin}.",
                TargetPath = candidate.Path,
                Recommendation =
                    "Do not run it. Ask Windows Security to scan this exact path — it is the tool " +
                    "that decides whether a file is harmful, and Ballast deliberately does not. If " +
                    "the file is also set to start with Windows, you can turn that entry off here; " +
                    "the entry is moved to a backup store rather than deleted.",
                CanDisableStartupEntry = candidate.Entry is { IsEnabled: true },
            });
        }

        return Task.FromResult<IReadOnlyList<SecurityFinding>>(findings);
    }

    private static string SafeFileName(string path)
    {
        try
        {
            return Path.GetFileName(path);
        }
        catch
        {
            // Illegal characters in a registry-sourced path. Cannot tell means stay silent.
            return string.Empty;
        }
    }
}
