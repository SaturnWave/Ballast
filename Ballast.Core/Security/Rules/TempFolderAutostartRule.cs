using Ballast.Core.Startup;

namespace Ballast.Core.Security.Rules;

/// <summary>
/// Auto-start entries that launch something out of scratch space — a Temp folder, the Recycle
/// Bin, or a Downloads folder.
/// </summary>
public sealed class TempFolderAutostartRule : ISecurityRule
{
    public string RuleId => "BAL-AUTOSTART-TEMP";

    public string Name => "Programs starting from temporary folders";

    public string Rationale =>
        "Installed software lives in Program Files, or in a versioned folder under AppData for " +
        "per-user installs. It does not live in Temp, and it certainly does not live in the " +
        "Recycle Bin. Temp folders are cleared by Windows and by this very app, so nothing that " +
        "expects to keep working would choose to run from there — which is precisely why a " +
        "scratch folder is an attractive place to be launched from.\n\n" +
        "A Temp folder or the Recycle Bin is High because the location itself is the anomaly and " +
        "needs no other evidence.\n\n" +
        "Downloads is deliberately not High, changed after running against a real machine. The " +
        "rationale here already conceded that a person who sets a downloaded portable program to " +
        "start automatically produces exactly this pattern on purpose — and a finding cannot admit " +
        "that and still rank itself as needing attention today. Downloads is now Medium, and Low " +
        "when the program carries a valid signature, since a signed portable tool has a publisher " +
        "who can be named and the folder is then the only unusual thing about it. Temp and the " +
        "Recycle Bin are unchanged and stay High whatever the signature says: an installer may " +
        "legitimately run from Temp, but nothing legitimate arranges to keep starting from there.\n\n" +
        "Deliberately NOT flagged: entries that are already disabled; anything under Program " +
        "Files, ProgramData or a normal AppData program folder. The folder name is matched as a " +
        "whole path segment, so a folder called \"Template\" or \"Temperature\" is not mistaken " +
        "for \"Temp\".";

    public async Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<SecurityFinding>();

        foreach (var entry in context.StartupEntries)
        {
            ct.ThrowIfCancellationRequested();

            if (!entry.IsEnabled) continue;

            var path = entry.ExecutablePath;
            if (!PathFacts.IsLocatable(path)) continue;

            var scratch = PathFacts.IsTempLike(path!);
            if (!scratch && !PathFacts.IsDownloads(path!)) continue;

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = "Starts with Windows from " + PathFacts.DescribeLocation(path!),
                Severity = scratch
                    ? FindingSeverity.High
                    : await DownloadsSeverityAsync(context, path!, ct).ConfigureAwait(false),
                Explanation = Explain(path!),
                Evidence =
                    $"\"{entry.DisplayName}\" runs at sign-in from {path}, registered under " +
                    $"{entry.Source.DisplayName()} at {entry.Location}.",
                TargetPath = path,
                Recommendation =
                    "If you put this here yourself — a portable program you downloaded, say — it is " +
                    "doing what you asked. Otherwise, turn it off here (the entry is moved to a " +
                    "backup store and can be restored) and ask Windows Security to scan the file. " +
                    "Ballast does not remove anything by itself.",
                CanDisableStartupEntry = true,
            });
        }

        return findings;
    }

    /// <summary>
    /// How loudly to report a Downloads folder. Never High: the rule's own reasoning is that a
    /// person who tells a downloaded portable program to start with Windows produces exactly this,
    /// and a finding cannot both concede that and demand to be read today.
    /// </summary>
    private static async Task<FindingSeverity> DownloadsSeverityAsync(
        SecurityScanContext context,
        string path,
        CancellationToken ct)
    {
        var signature = await context.SignatureOfAsync(path, ct).ConfigureAwait(false);

        // A validly signed program has a publisher who can be named, so the only thing left that
        // is unusual is the folder. That is worth mentioning and nothing more.
        return signature.Status == SignatureStatus.Valid || signature.IsMicrosoft
            ? FindingSeverity.Low
            : FindingSeverity.Medium;
    }

    private static string Explain(string path)
    {
        if (PathFacts.IsRecycleBin(path))
        {
            return "Something is set to run at sign-in from inside the Recycle Bin. Deleted files " +
                   "are not supposed to be running at all, and no installer puts a program there.";
        }

        if (PathFacts.IsTempLike(path))
        {
            return "Something is set to run at sign-in from a temporary folder. Temp is cleared " +
                   "routinely — by Windows, and by Ballast's own cleaning — so software that " +
                   "intends to keep working is never installed there. A leftover entry from a " +
                   "half-finished install can look like this too, in which case it is simply dead " +
                   "weight and safe to turn off.";
        }

        return "Something is set to run at sign-in directly out of a Downloads folder. That happens " +
               "innocently when you tell a downloaded portable program to start with Windows. It is " +
               "worth confirming this is one of those, because a Downloads folder is where files " +
               "arrive from elsewhere and is not where installed software normally ends up.";
    }
}
