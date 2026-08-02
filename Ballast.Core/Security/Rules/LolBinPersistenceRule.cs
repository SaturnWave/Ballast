using Ballast.Core.Startup;

namespace Ballast.Core.Security.Rules;

/// <summary>
/// Auto-start entries that do not start a program of their own but hand work to a built-in
/// Windows tool — the "living off the land" pattern.
/// </summary>
public sealed class LolBinPersistenceRule : ISecurityRule
{
    /// <summary>
    /// Built-in Windows programs whose job is to run something else. Every one of these is signed
    /// by Microsoft and lives in System32, so checking the signature of the entry itself proves
    /// nothing — what matters is what it has been pointed at.
    /// </summary>
    private static readonly HashSet<string> HelperBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "mshta", "rundll32", "regsvr32", "wscript", "cscript", "powershell", "pwsh",
        "cmd", "bitsadmin", "certutil", "msiexec", "installutil",
    };

    public string RuleId => "BAL-LOLBIN-PERSISTENCE";

    public string Name => "Sign-in entries that run through a Windows helper tool";

    public string Rationale =>
        "Some auto-start entries do not name a program. They name one of Windows' own tools — " +
        "rundll32, mshta, powershell, regsvr32 — and hand it something to run. Doing so means no " +
        "program of your own has to exist on disk to be examined, which is why it is a favoured " +
        "persistence shape; it is also, genuinely, how several printer and graphics drivers set " +
        "themselves up. Medium is the honest level for the plain case: unusual enough to read, " +
        "not evidence of anything. It becomes High when the tool is pointed at something remote — " +
        "an http address or a network share — or when the command line is obscured, because " +
        "neither has an ordinary explanation.\n\n" +
        "Deliberately NOT flagged: an entry whose payload carries a valid signature and does not " +
        "sit in a temporary folder. A signed DLL handed to rundll32 is the normal driver pattern " +
        "and flagging it would put a Medium finding on a large share of clean machines, which is " +
        "the fastest way to teach someone to ignore this page. Disabled entries are skipped as " +
        "well, since they do not run.\n\n" +
        "Narrowed after running against a real machine, where the plain case reported six " +
        "ordinary things. Everything the rule could not resolve used to fall through to a Medium " +
        "finding, which is the opposite of how the rest of this app treats uncertainty. Now the " +
        "plain case says nothing unless it can actually point at a payload and find it wanting. " +
        "Specifically it no longer reports: a payload somewhere a standard user cannot write — the " +
        "Windows folder or either Program Files tree, in plain or %windir%/%ProgramFiles% form — " +
        "which covers .cmd and .bat files, since those cannot carry a signature anywhere and so " +
        "could never be cleared by a signature check (two stock Windows tasks and any machine " +
        "with Node's npm.cmd on it were being flagged for this alone); a payload named with an " +
        "environment variable, which is now resolved for the " +
        "signature check rather than treated as unknown; a payload that is a bare name resolved " +
        "through PATH, such as rundll32.exe shell32.dll,Control_RunDLL; a command with no " +
        "identifiable payload at all, such as MsiExec.exe /fu {GUID} — Windows Installer " +
        "self-repair — or cmd.exe /c echo; and a payload the verifier could not read. The remote " +
        "and obscured cases are untouched: those are the signal this rule exists for and they " +
        "still report High regardless of any of the above.";

    public async Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<SecurityFinding>();

        foreach (var entry in context.StartupEntries)
        {
            ct.ThrowIfCancellationRequested();

            if (!entry.IsEnabled) continue;

            var program = CommandFacts.ProgramFileName(entry.Command);
            if (program.Length == 0) continue;

            var bare = Path.GetFileNameWithoutExtension(program);
            if (!HelperBinaries.Contains(bare)) continue;

            var arguments = CommandFacts.Arguments(entry.Command);
            var remote = arguments.FirstOrDefault(CommandFacts.IsRemoteReference);
            var obscured = CommandFacts.StrongObfuscationMarker(entry.Command);
            var payload = CommandFacts.FirstPayloadReference(arguments);

            if (remote is null && obscured is null && !await WorthReportingAsync(context, payload, ct).ConfigureAwait(false))
                continue;

            var severity = remote is not null || obscured is not null ? FindingSeverity.High : FindingSeverity.Medium;

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = $"Starts with Windows by way of {bare}",
                Severity = severity,
                Explanation = Explain(bare, remote, obscured),
                Evidence =
                    $"\"{entry.DisplayName}\" runs at sign-in: {CommandFacts.Ellipsis(entry.Command, 220)} " +
                    $"({entry.Source.DisplayName()}, {entry.Location})" +
                    (remote is not null ? $". Points at {CommandFacts.Ellipsis(remote, 120)}" : string.Empty) +
                    (obscured is not null ? $". Command line uses {obscured}" : string.Empty) +
                    (remote is null && payload is { Length: > 0 } p ? $". Loads {CommandFacts.Ellipsis(p, 120)}" : string.Empty) +
                    ".",
                TargetPath = PathFacts.IsLocatable(payload) ? payload : entry.ExecutablePath,
                Recommendation =
                    "Read the command above and see whether you can account for it — driver and " +
                    "printer software does legitimately look like this. If you cannot, turn the " +
                    "entry off here (it is moved to a backup store and can be restored) and ask " +
                    "Windows Security to scan the file it points at.",
                CanDisableStartupEntry = true,
            });
        }

        return findings;
    }

    /// <summary>
    /// Whether the plain case — no remote reference, no obscured command line — has anything a
    /// person could act on. Only reached when the entry is not already High.
    /// </summary>
    /// <remarks>
    /// This is the "cannot tell means stay silent" test, and it is here because the rule used to
    /// get it backwards. Anything it could not resolve fell through to a Medium finding, so
    /// <c>%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask</c> — a
    /// stock Windows task — was reported, as was <c>MsiExec.exe /fu {GUID}</c> and
    /// <c>rundll32.exe shell32.dll,Control_RunDLL</c>. An unresolvable payload is not evidence;
    /// it is the absence of evidence, and reporting it is how a page earns the reader's contempt.
    /// </remarks>
    private static async Task<bool> WorthReportingAsync(
        SecurityScanContext context,
        string? payload,
        CancellationToken ct)
    {
        // Nothing identifiable was handed over. There is no payload to have an opinion about.
        if (payload is not { Length: > 0 } file) return false;

        // Scratch space is the exception that needs no signature: nothing that means to keep
        // working is loaded from Temp or the Recycle Bin.
        if (PathFacts.IsTempLike(file)) return true;

        // Somewhere a standard user cannot write. Putting a file there already needs administrator
        // rights, and a great many stock tasks and installed programs hand cmd or rundll32 a
        // script out of System32 or Program Files — including .cmd and .bat files, which cannot
        // carry an Authenticode signature at all, so no signature check could ever clear them.
        if (PathFacts.RequiresAdminToWrite(file)) return false;

        // A bare name resolved through PATH. The rule is about what the tool was pointed at,
        // so when that cannot be established the rule has nothing to say.
        if (!PathFacts.CanLocate(file)) return false;

        var signature = await context.SignatureOfAsync(file, ct).ConfigureAwait(false);

        // A signed payload in a normal location is the ordinary driver/updater shape. Unreadable
        // is not a milder form of unsigned: it means the file could not be examined, so it too
        // leaves the rule with nothing to report.
        return signature.Status is not (SignatureStatus.Valid or SignatureStatus.Unreadable)
               && !signature.IsMicrosoft;
    }

    private static string Explain(string tool, string? remote, string? obscured)
    {
        var head =
            $"This entry does not start a program of its own. It starts {tool}, a tool built into " +
            "Windows, and gives it something to run. That is a legitimate arrangement for some " +
            "drivers and installers, and it is also the usual way to arrange for code to run at " +
            "every sign-in without leaving a program of your own on disk to be inspected.";

        if (remote is not null)
        {
            return head +
                   " In this case it is pointed at something that is not on this PC — a web address " +
                   "or a network location — so what actually runs is decided elsewhere and can " +
                   "change at any time. That is why this one is ranked higher.";
        }

        if (obscured is not null)
        {
            return head +
                   " In this case the command line is also written so that what it does cannot be " +
                   "read directly, which ordinary software has no reason to do.";
        }

        return head + " It is worth reading the command below and recognising what it points at.";
    }
}
