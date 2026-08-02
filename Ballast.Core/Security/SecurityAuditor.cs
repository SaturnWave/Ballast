using Ballast.Core.Models;
using Ballast.Core.Programs;
using Ballast.Core.Security.Rules;
using Ballast.Core.Startup;
using Ballast.Core.Util;

namespace Ballast.Core.Security;

/// <summary>
/// Runs every registered <see cref="ISecurityRule"/> against one shared
/// <see cref="SecurityScanContext"/> and returns what they noticed.
/// </summary>
/// <remarks>
/// <para>
/// This is a review, not a scan in the antivirus sense. It reads the machine's auto-start
/// configuration, its installed-program list and its hosts file, applies behavioural and
/// structural heuristics, and reports. It never quarantines, deletes, repairs or disables
/// anything: the only action any finding can offer is the existing reversible startup toggle,
/// and even that is the user's to press.
/// </para>
/// <para>
/// The context is built once. Twenty rules asking the registry twenty times would make the audit
/// unusable, and worse, would let two rules disagree because the machine changed underneath them.
/// </para>
/// </remarks>
public sealed class SecurityAuditor
{
    /// <summary>
    /// Deliberately includes the <c>\Microsoft\</c> task namespace, unlike the Startup page's scanner.
    /// </summary>
    /// <remarks>
    /// The Startup <em>manager</em> hides those tasks for a good reason: someone browsing a list of
    /// things to switch off should not be invited to disable the operating system. A security
    /// <em>audit</em> has the opposite requirement. Measured on a real machine, 33 logon-triggered
    /// tasks existed and 32 of them lived under <c>\Microsoft\</c> — so the default left the audit
    /// blind to the most conventional hiding place there is.
    ///
    /// <para>
    /// Findings on those tasks are reported but never offered a switch — see
    /// <see cref="WithoutOsTaskToggles"/>.
    /// </para>
    /// </remarks>
    private readonly StartupScanner _startupScanner = new() { IncludeMicrosoftTasks = true };

    private readonly InstalledProgramScanner _programScanner = new();

    public SecurityAuditor() : this(DefaultRules()) { }

    public SecurityAuditor(IEnumerable<ISecurityRule> rules) =>
        Rules = rules?.ToArray() ?? throw new ArgumentNullException(nameof(rules));

    /// <summary>
    /// The rules that will run, in order. Exposed so the UI can show what was checked and why —
    /// a security feature that will not say what it looked at is asking to be taken on faith.
    /// </summary>
    public IReadOnlyList<ISecurityRule> Rules { get; }

    /// <summary>
    /// Include scheduled tasks in the audit. On by default: Task Scheduler is one of the main
    /// places persistence lives, so leaving it out would be a hole.
    ///
    /// <para>
    /// It is also, on its own, the entire cost of the audit — <c>schtasks /query /v</c> was
    /// measured at 18 s here against 160 ms for everything else put together. A caller that wants
    /// a result on screen immediately can turn this off, show the rest, and run a full pass after;
    /// what it must not do is quietly leave it off and present the result as a complete review.
    /// </para>
    /// </summary>
    public bool IncludeScheduledTasks { get; init; } = true;

    /// <summary>The rules shipped with the app.</summary>
    /// <param name="hostsFilePath">Overrides the hosts file location; for tests only.</param>
    public static IReadOnlyList<ISecurityRule> DefaultRules(string? hostsFilePath = null) =>
    [
        new UnsignedAutostartRule(),
        new TempFolderAutostartRule(),
        new SystemBinaryMasqueradeRule(),
        new DoubleExtensionRule(),
        new LolBinPersistenceRule(),
        new ObscuredCommandRule(),
        new HostsFileRule(hostsFilePath),
    ];

    /// <summary>Gathers the context, then runs every rule against it.</summary>
    public async Task<IReadOnlyList<SecurityFinding>> RunAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var context = await BuildContextAsync(progress, ct).ConfigureAwait(false);
        return await RunRulesAsync(context, progress, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the machine once. A scanner that fails is logged and treated as an empty list: a
    /// partial audit is worth more than no audit, and silently returning nothing at all would be
    /// the one outcome a user cannot tell apart from "everything is fine".
    /// </summary>
    public async Task<SecurityScanContext> BuildContextAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        var total = Rules.Count + 2;

        Report(progress, "Reading start-up entries", 0, 0, total);

        // Scheduled tasks are started first so everything else overlaps them. Measured on a real
        // machine: schtasks 18 s, the Run keys and startup folders 650 ms, the uninstall registry
        // 134 ms. The audit is bounded by schtasks and nothing else, which is exactly why
        // IncludeScheduledTasks exists — without it the context is ready in about 160 ms.
        var tasksJob = IncludeScheduledTasks
            ? SafelyAsync(() => _startupScanner.ScanScheduledTasksAsync(ct), "scheduled tasks", Array.Empty<StartupEntry>())
            : Task.FromResult<IReadOnlyList<StartupEntry>>([]);

        var programsJob = SafelyAsync(
            () => _programScanner.ScanAsync(ct),
            "installed programs",
            Array.Empty<InstalledProgram>());

        var startup = await SafelyAsync(
            () => _startupScanner.ScanFastAsync(ct),
            "startup entries",
            Array.Empty<StartupEntry>()).ConfigureAwait(false);

        if (IncludeScheduledTasks) Report(progress, "Reading scheduled tasks", 0, 1, total);

        var tasks = await tasksJob.ConfigureAwait(false);
        if (tasks.Count > 0) startup = StartupScanner.Deduplicate(startup.Concat(tasks));

        Report(progress, "Reading installed programs", 0, 2, total);
        var programs = await programsJob.ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();

        return new SecurityScanContext
        {
            StartupEntries = startup,
            InstalledPrograms = programs,
            Signatures = new AuthenticodeVerifier(),
        };
    }

    /// <summary>
    /// Strips the "turn this off" affordance from findings that land on an operating-system
    /// scheduled task, wherever they came from.
    /// </summary>
    /// <remarks>
    /// This is a policy decision, not a rule detail, so it lives in one place rather than being
    /// repeated in every rule that sets <see cref="SecurityFinding.CanDisableStartupEntry"/>.
    /// Centralising it means a rule written later cannot forget it.
    ///
    /// <para>
    /// The finding is still shown. Suppressing the button is not the same as suppressing the
    /// warning: if something genuinely is hiding under <c>\Microsoft\</c>, the user needs to know
    /// even though the right response is Defender and Task Scheduler rather than a switch here.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<SecurityFinding> WithoutOsTaskToggles(
        IReadOnlyList<SecurityFinding> findings,
        SecurityScanContext context)
    {
        // Task paths, not file paths: only a scheduled task carries a \Microsoft\ namespace.
        var osTaskLocations = new HashSet<string>(
            context.StartupEntries
                .Where(e => e.Source is StartupSource.ScheduledTask
                            && e.Location.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
                .Select(e => e.Location),
            StringComparer.OrdinalIgnoreCase);

        if (osTaskLocations.Count == 0) return findings;

        return findings
            .Select(f => f.CanDisableStartupEntry
                         && f.TargetPath is { } path
                         && osTaskLocations.Contains(path)
                ? f with
                {
                    CanDisableStartupEntry = false,
                    Recommendation = f.Recommendation is { Length: > 0 } existing
                        ? existing + " This is a Windows scheduled task, so review it in Task Scheduler rather than switching it off here."
                        : "This is a Windows scheduled task. Review it in Task Scheduler rather than switching it off here.",
                }
                : f)
            .ToArray();
    }

    /// <summary>
    /// Runs the rules against an already-built context. Separate from <see cref="RunAsync"/> so
    /// the engine can be exercised against a synthetic machine.
    /// </summary>
    public async Task<IReadOnlyList<SecurityFinding>> RunRulesAsync(
        SecurityScanContext context,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var collected = new List<SecurityFinding>();
        var total = Rules.Count + 2;
        var step = 2;

        foreach (var rule in Rules)
        {
            ct.ThrowIfCancellationRequested();
            Report(progress, rule.Name, collected.Count, step++, total);

            try
            {
                var found = await rule.EvaluateAsync(context, ct).ConfigureAwait(false);
                if (found is { Count: > 0 }) collected.AddRange(found.Where(f => f is not null));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // One rule must never cost the whole audit. Logged rather than swallowed, because
                // a check that quietly stopped running is indistinguishable from a check that
                // found nothing — and that is the failure mode this app cannot afford.
                ActionLog.Write($"SECURITY rule '{rule.RuleId}' failed and was skipped -- {ex.GetType().Name}: {ex.Message}");
            }
        }

        var findings = WithoutOsTaskToggles(Consolidate(collected), context);

        ActionLog.Info(
            $"Security review: {Rules.Count} rules, {findings.Count} finding(s) " +
            $"({findings.Count(f => f.Severity == FindingSeverity.High)} high). Nothing was changed.");

        Report(progress, "Finished", findings.Count, total, total);
        return findings;
    }

    /// <summary>
    /// Drops repeats and orders the result for a reader: most urgent first.
    /// </summary>
    /// <remarks>
    /// The same program is frequently registered in two stores at once (a Run key and a Startup
    /// folder shortcut), so one rule can legitimately produce the identical observation twice.
    /// The key includes the title as well as the path, because a rule that says two <em>different</em>
    /// things about one file — the hosts file both redirecting and blocking, say — is not repeating
    /// itself, and throwing one of those away would lose a real finding.
    /// </remarks>
    private static IReadOnlyList<SecurityFinding> Consolidate(IEnumerable<SecurityFinding> raw)
    {
        var best = new Dictionary<string, SecurityFinding>(StringComparer.OrdinalIgnoreCase);

        foreach (var finding in raw)
        {
            // Unit separator: it cannot occur in a path or a title, so the parts cannot run together.
            var key = string.Join('\u001f', finding.RuleId, finding.TargetPath ?? string.Empty, finding.Title);

            if (!best.TryGetValue(key, out var existing) || finding.Severity > existing.Severity)
                best[key] = finding;
        }

        return best.Values
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId, StringComparer.Ordinal)
            .ThenBy(f => f.Title, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(f => f.TargetPath ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task<IReadOnlyList<T>> SafelyAsync<T>(
        Func<Task<IReadOnlyList<T>>> work,
        string what,
        IReadOnlyList<T> fallback)
    {
        try
        {
            return await work().ConfigureAwait(false) ?? fallback;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            ActionLog.Write($"SECURITY could not read {what} -- {ex.GetType().Name}: {ex.Message}");
            return fallback;
        }
    }

    private static void Report(IProgress<ScanProgress>? progress, string label, int found, int step, int total) =>
        progress?.Report(new ScanProgress(label, found, 0, total <= 0 ? null : Math.Clamp((double)step / total, 0, 1)));
}
