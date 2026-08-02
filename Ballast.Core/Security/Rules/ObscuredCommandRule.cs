using Ballast.Core.Startup;

namespace Ballast.Core.Security.Rules;

/// <summary>
/// Auto-start commands written so that what they do cannot be read: encoded payloads, hidden
/// windows, text executed as code.
/// </summary>
public sealed class ObscuredCommandRule : ISecurityRule
{
    public string RuleId => "BAL-ENCODED-COMMAND";

    public string Name => "Sign-in commands that hide what they run";

    public string Rationale =>
        "A start-up command is a public record of what a program does at sign-in. Base64-encoding " +
        "it, forcing the window hidden, or piping text into Invoke-Expression all have the same " +
        "effect: the record stops being readable. Installers, drivers and updaters have no reason " +
        "to hide their own command line from the person who owns the PC, so the strong markers " +
        "here are High.\n\n" +
        "Deliberately NOT flagged at High: -NoProfile, -NonInteractive and a relaxed execution " +
        "policy, in any combination. Package managers, build tools and IT deployment scripts use " +
        "those constantly and they hide nothing. The abbreviated -e switch only counts when what " +
        "follows it actually looks encoded, and Invoke-Expression is matched as a whole token so " +
        "that a folder whose name happens to contain \"iex\" cannot trip it. Disabled entries are " +
        "skipped.\n\n" +
        "Two changes after running against a real machine. Those relaxed switches used to reach " +
        "High once two of them appeared together, which is precisely the shape of the standard " +
        "Chocolatey and corporate logon script — a finding whose own explanation said \"routine " +
        "for package managers\" while ranking itself as needing attention today. They are now Low " +
        "however many appear, and High is reserved for the strong markers alone. Second, every " +
        "switch-shaped marker is now only read when a PowerShell host is actually named in the " +
        "command: -e, -w and -nop are PowerShell's spellings, and on another program they are " +
        "just letters. An ordinary program invoked as \"sync.exe -e <session token>\" was being " +
        "reported at High as written-to-be-unreadable. Invoke-Expression, FromBase64String and " +
        "DownloadString stay ungated, because those are PowerShell code wherever they appear.";

    public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<SecurityFinding>();

        foreach (var entry in context.StartupEntries)
        {
            ct.ThrowIfCancellationRequested();

            if (!entry.IsEnabled) continue;

            var strong = CommandFacts.StrongObfuscationMarker(entry.Command);
            var weak = CommandFacts.WeakObfuscationMarkers(entry.Command);

            if (strong is null && weak.Count == 0) continue;

            // Weak markers never reach High, however many of them there are. A finding that says
            // "this is routine for package managers" in its own explanation cannot also demand
            // to be looked at today; -NoProfile with -ExecutionPolicy Bypass is the standard
            // Chocolatey and corporate-deployment invocation and used to score exactly that.
            var severity = strong is not null ? FindingSeverity.High : FindingSeverity.Low;
            var markers = strong is not null ? new[] { strong }.Concat(weak).ToArray() : weak.ToArray();

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = strong is not null
                    ? "A sign-in command is written to be unreadable"
                    : "A sign-in command runs a PowerShell script with its usual checks relaxed",
                Severity = severity,
                Explanation = strong is not null
                    ? "This command runs at every sign-in and is written so that what it actually " +
                      "does cannot be read from it — the instructions are encoded, executed from " +
                      "text, or told to run without a visible window. Legitimate software has no " +
                      "reason to hide its own command line, which is why this is worth looking at " +
                      "today rather than eventually."
                    : "This command runs a PowerShell script at every sign-in with some of the " +
                      "usual safeguards switched off. Package managers, build tools and company " +
                      "deployment scripts do this constantly and it hides nothing, so it is listed " +
                      "for recognition rather than for concern: the useful question is simply " +
                      "which of yours it is.",
                Evidence =
                    $"\"{entry.DisplayName}\": {CommandFacts.Ellipsis(entry.Command, 220)} " +
                    $"({entry.Source.DisplayName()}, {entry.Location}). " +
                    $"Noticed: {string.Join(", ", markers.Select(m => CommandFacts.Ellipsis(m, 60)))}.",
                TargetPath = entry.ExecutablePath,
                Recommendation =
                    "If this is yours — a deployment script, a package manager — it is doing what " +
                    "you set up. If it is not, turn the entry off here; Ballast moves it to a " +
                    "backup store so it can be restored, and it does not delete anything. Windows " +
                    "Security is the tool to ask about the file itself.",
                CanDisableStartupEntry = true,
            });
        }

        return Task.FromResult<IReadOnlyList<SecurityFinding>>(findings);
    }
}
