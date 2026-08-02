using Ballast.Core.Startup;

namespace Ballast.Core.Security.Rules;

/// <summary>
/// Auto-start entries whose executable carries no signature Windows is willing to trust.
/// </summary>
public sealed class UnsignedAutostartRule : ISecurityRule
{
    public string RuleId => "BAL-AUTOSTART-UNSIGNED";

    public string Name => "Unsigned programs that start with Windows";

    public string Rationale =>
        "A digital signature is the only thing that ties a program to a company that can be held " +
        "responsible for it. Something that runs on every sign-in without one cannot be traced back " +
        "to anybody, so it is worth being able to name it.\n\n" +
        "This is Medium and not a verdict because a great many perfectly ordinary tools are " +
        "unsigned — certificates cost money every year, and small utilities, open-source programs " +
        "and internal company tools routinely ship without one. Being unsigned is a reason to " +
        "recognise a program, not a reason to distrust it.\n\n" +
        "Deliberately NOT flagged: anything signed by Microsoft; anything with a valid signature; " +
        "anything with a merely expired signature, since a certificate that has run out says " +
        "nothing about the file it signed; anything the verifier could not read, because cannot " +
        "tell must mean stay silent; entries that are already disabled, because they do not run; " +
        "and entries whose executable cannot be located, because a rule that cannot find the file " +
        "has no business judging it. The severity is only raised for a genuinely out-of-place " +
        "location — never merely for living under AppData, where a large share of ordinary " +
        "software installs itself.";

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

            var signature = await context.SignatureOfAsync(path!, ct).ConfigureAwait(false);

            // A Microsoft binary is out of scope whatever its certificate is doing today.
            if (signature.IsMicrosoft) continue;

            if (signature.Status is not (SignatureStatus.Unsigned or SignatureStatus.Untrusted or SignatureStatus.Revoked))
                continue;

            var outOfPlace = PathFacts.IsOutOfPlaceLocation(path!);

            // Revoked is the one status that is stronger than "unknown publisher": the issuing
            // authority withdrew the certificate after issuing it, which is a deliberate act.
            var severity = signature.Status == SignatureStatus.Revoked || outOfPlace
                ? FindingSeverity.High
                : FindingSeverity.Medium;

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = Describe(signature.Status) + " program starts with Windows",
                Severity = severity,
                Explanation = Explain(signature.Status, outOfPlace),
                Evidence =
                    $"\"{entry.DisplayName}\" runs at sign-in from {path}. " +
                    $"Signature: {Describe(signature.Status).ToLowerInvariant()}" +
                    (signature.SignerName is { Length: > 0 } signer ? $" (signed by {signer})" : string.Empty) +
                    $". Registered under {entry.Source.DisplayName()} at {entry.Location}.",
                TargetPath = path,
                Recommendation =
                    "If you recognise the program, nothing needs doing. If you do not, you can turn " +
                    "it off here — Ballast moves the entry to a backup store, so it can be put back " +
                    "exactly as it was — and ask Windows Security to scan the file. Deciding whether " +
                    "a file is harmful is Windows Security's job, not this app's.",
                CanDisableStartupEntry = true,
            });
        }

        return findings;
    }

    private static string Describe(SignatureStatus status) => status switch
    {
        SignatureStatus.Unsigned  => "Unsigned",
        SignatureStatus.Untrusted => "Untrusted-certificate",
        SignatureStatus.Revoked   => "Revoked-certificate",
        _ => status.ToString(),
    };

    private static string Explain(SignatureStatus status, bool outOfPlace)
    {
        var head = status switch
        {
            SignatureStatus.Revoked =>
                "This program runs every time you sign in, and the certificate it was signed with " +
                "has since been withdrawn by the authority that issued it. That withdrawal is a " +
                "deliberate act by someone, so it is worth finding out why.",

            SignatureStatus.Untrusted =>
                "This program runs every time you sign in, and it is signed with a certificate this " +
                "PC does not trust — typically a self-issued one. That is normal for an in-house or " +
                "hobby tool and unusual for commercial software.",

            _ =>
                "This program runs every time you sign in and carries no digital signature, so " +
                "Windows cannot tell you who published it. Plenty of legitimate small tools are " +
                "unsigned, so this is not a judgement about the program — it is a prompt to check " +
                "that you know what it is.",
        };

        return outOfPlace
            ? head + " It also runs from a location where installed software does not normally live, which is why this is ranked higher."
            : head;
    }
}
