using System.Collections.Concurrent;
using Ballast.Core.Programs;
using Ballast.Core.Startup;

namespace Ballast.Core.Security;

/// <summary>
/// How much attention a <see cref="SecurityFinding"/> is asking for. Deliberately not a
/// confidence score and never a verdict: <see cref="High"/> means "look at this first",
/// not "this is harmful".
/// </summary>
public enum FindingSeverity
{
    /// <summary>Context worth having. Nothing is unusual about it.</summary>
    Info = 0,

    /// <summary>Slightly out of the ordinary. Read it when convenient.</summary>
    Low = 1,

    /// <summary>Unusual enough to be worth recognising before leaving it alone.</summary>
    Medium = 2,

    /// <summary>Unusual enough that a person should look at it today.</summary>
    High = 3,
}

/// <summary>
/// One thing worth a human's attention. Never a verdict.
/// </summary>
/// <remarks>
/// <para>
/// Ballast is not an antivirus and a finding is not a detection. Every rule in this namespace is
/// behavioural or structural: it observes a fact about how something is configured and says why
/// that fact is unusual. Deciding whether a file is harmful is Windows Security's job, and the
/// wording here defers to it rather than competing with it.
/// </para>
/// <para>
/// Nothing here removes, quarantines or repairs anything. The only action a finding can offer is
/// <see cref="CanDisableStartupEntry"/>, which routes through the existing reversible
/// <see cref="StartupToggleService"/> — the entry is moved to a backup store, never deleted.
/// </para>
/// </remarks>
public sealed record SecurityFinding
{
    /// <summary>Stable identifier for the rule that produced this, e.g. <c>BAL-AUTOSTART-UNSIGNED</c>.</summary>
    public required string RuleId { get; init; }

    /// <summary>Short, neutral headline. Describes the observation, not a conclusion about it.</summary>
    public required string Title { get; init; }

    public required FindingSeverity Severity { get; init; }

    /// <summary>
    /// Plain language: why this is worth a look, and — just as important — why it might be
    /// perfectly ordinary. A finding that only argues one side trains the reader to ignore it.
    /// </summary>
    public required string Explanation { get; init; }

    /// <summary>The concrete observed fact, quoted rather than summarised, so the user can check it.</summary>
    public required string Evidence { get; init; }

    /// <summary>The file or store the finding is about, when there is one.</summary>
    public string? TargetPath { get; init; }

    /// <summary>What the user might do. Never something the app does on its own.</summary>
    public string? Recommendation { get; init; }

    /// <summary>
    /// True when the finding is about an enabled auto-start entry, so the UI may offer the
    /// reversible disable action. Never implies the entry should be disabled.
    /// </summary>
    public bool CanDisableStartupEntry { get; init; }
}

/// <summary>
/// One heuristic. Rules are pure with respect to the machine: they read the shared
/// <see cref="SecurityScanContext"/> and return findings, and they never change anything.
/// </summary>
public interface ISecurityRule
{
    /// <summary>Stable identifier, also carried on every finding this rule produces.</summary>
    string RuleId { get; }

    /// <summary>Short name for the "what was checked" list in the UI.</summary>
    string Name { get; }

    /// <summary>
    /// Why this rule exists and what it deliberately does NOT flag. The second half is the
    /// important half: false positives are the expensive failure here, so every exclusion a rule
    /// makes is written down where a reviewer can argue with it.
    /// </summary>
    string Rationale { get; }

    Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(SecurityScanContext context, CancellationToken ct = default);
}

/// <summary>
/// Everything the rules share, gathered once so 20 rules do not each re-enumerate the registry.
/// </summary>
/// <remarks>
/// Rules must treat this as read-only and must not go back to the disk for anything it already
/// holds. Signature results are memoised here for the same reason: several rules ask about the
/// same handful of executables, and Authenticode verification is the expensive part of an audit.
/// </remarks>
public sealed class SecurityScanContext
{
    private readonly ConcurrentDictionary<string, Task<SignatureInfo>> _signatureCache =
        new(StringComparer.OrdinalIgnoreCase);

    public required IReadOnlyList<StartupEntry> StartupEntries { get; init; }

    public required IReadOnlyList<InstalledProgram> InstalledPrograms { get; init; }

    /// <summary>The shared verifier. Reach it through <see cref="SignatureOfAsync"/>, not directly.</summary>
    public required AuthenticodeVerifier Signatures { get; init; }

    /// <summary>
    /// Substitutes for <see cref="Signatures"/> when set. This exists so rule tests can assert
    /// rule <em>logic</em> against known signature states instead of against whatever happens to
    /// be installed on the machine running the tests — a security rule whose test outcome depends
    /// on the test machine is not a test of the rule.
    /// </summary>
    public Func<string, CancellationToken, Task<SignatureInfo>>? SignatureLookup { get; init; }

    /// <summary>
    /// The signature of a file, memoised per path for the lifetime of one audit. Never throws:
    /// a verifier that fails is reported as <see cref="SignatureStatus.Unreadable"/>, which every
    /// rule treats as "cannot tell", and *cannot tell* means stay silent.
    /// </summary>
    public Task<SignatureInfo> SignatureOfAsync(string filePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return Task.FromResult(new SignatureInfo(SignatureStatus.Unreadable, null, false));

        return _signatureCache.GetOrAdd(filePath, static (path, state) => Lookup(path, state.Context, state.Token),
            (Context: this, Token: ct));
    }

    private static async Task<SignatureInfo> Lookup(string path, SecurityScanContext context, CancellationToken ct)
    {
        try
        {
            return context.SignatureLookup is { } custom
                ? await custom(path, ct).ConfigureAwait(false)
                : await context.Signatures.VerifyAsync(path, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return new SignatureInfo(SignatureStatus.Unreadable, null, false);
        }
    }
}
