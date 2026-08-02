using System.Collections.ObjectModel;
using System.Diagnostics;
using Ballast.Core.Models;
using Ballast.Core.Security;
using Ballast.Core.Startup;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>
/// One finding, ready to draw.
/// </summary>
/// <remarks>
/// <para>
/// A finding is an observation, never a verdict, and this class is where that distinction has to
/// survive contact with the UI. It exposes the rule's own words — evidence, explanation,
/// recommendation — and adds nothing of its own beyond a severity flag for the colour rule and the
/// three actions the page offers. It does not summarise, score, or re-word what the rule said.
/// </para>
/// <para>
/// The commands delegate straight back to <see cref="SecurityViewModel"/>. They live here rather
/// than on the page so the row can be bound with a plain <c>{Binding RevealCommand}</c>: a
/// <c>DataTemplate</c> declared in <c>Page.Resources</c> is its own namescope, so an
/// <c>ElementName</c> binding back out to the page does not resolve in WinUI 3.
/// </para>
/// </remarks>
public sealed partial class SecurityFindingViewModel : ObservableObject
{
    private readonly SecurityViewModel _page;

    /// <summary>Wraps <paramref name="finding"/> for display on <paramref name="page"/>.</summary>
    public SecurityFindingViewModel(SecurityViewModel page, SecurityFinding finding)
    {
        _page = page;
        Finding = finding;
    }

    /// <summary>The immutable Core record backing this row.</summary>
    public SecurityFinding Finding { get; }

    /// <summary>
    /// The startup entry this finding is about, once it has been resolved unambiguously.
    /// Null when the finding is not about a startup entry, or when the match was not certain.
    /// </summary>
    public StartupEntry? StartupEntry { get; private set; }

    /// <summary>Stable rule identifier, shown so a finding can be traced to the check that made it.</summary>
    public string RuleId => Finding.RuleId;

    /// <summary>Short, neutral headline.</summary>
    public string Title => Finding.Title;

    /// <summary>The concrete observed fact. Selectable, because it is the bit worth copying.</summary>
    public string Evidence => Finding.Evidence;

    /// <summary>Plain-language reason this is worth a look.</summary>
    public string Explanation => Finding.Explanation;

    /// <summary>What the user might do about it. Never something Ballast does by itself.</summary>
    public string RecommendationText => Finding.Recommendation ?? string.Empty;

    /// <summary>True when the rule offered a recommendation.</summary>
    public bool HasRecommendation => !string.IsNullOrWhiteSpace(Finding.Recommendation);

    /// <summary>The file this finding points at, or null.</summary>
    public string? TargetPath => Finding.TargetPath;

    /// <summary>True when there is a path to reveal or hand to Defender.</summary>
    public bool HasTargetPath => !string.IsNullOrWhiteSpace(Finding.TargetPath);

    /// <summary>High: drawn with <c>Risk1Brush</c>.</summary>
    public bool IsHigh => Finding.Severity is FindingSeverity.High;

    /// <summary>Medium: drawn with <c>Risk2Brush</c>.</summary>
    public bool IsMedium => Finding.Severity is FindingSeverity.Medium;

    /// <summary>Low: drawn with <c>Risk3Brush</c>.</summary>
    public bool IsLow => Finding.Severity is FindingSeverity.Low;

    /// <summary>Info: drawn in secondary ink, because it is not on the risk ramp at all.</summary>
    public bool IsInfo => Finding.Severity is FindingSeverity.Info;

    /// <summary>
    /// Offered only when exactly one enabled startup entry matched this finding and the toggle
    /// service is willing to change it.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TurnOffTooltip))]
    private bool _canTurnOffStartupEntry;

    /// <summary>What the row's last action actually did. Empty until something has been done.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActionNote))]
    private string _actionNote = string.Empty;

    /// <summary>True once <see cref="ActionNote"/> has something to say.</summary>
    public bool HasActionNote => ActionNote.Length > 0;

    /// <summary>Tooltip for the Defender button. Says plainly who decides what happens next.</summary>
    public string DefenderScanTooltip =>
        "Hands this path to Windows Defender and asks it to look. Defender decides what to do with " +
        "anything it finds, and reports it in Windows Security — Ballast neither sees nor changes " +
        "the outcome.";

    /// <summary>
    /// Tooltip for the startup button. Reversibility leads, and the entry is named: the finding
    /// points at a file, the button acts on an entry, and the user should be able to see that those
    /// are the same thing before pressing it.
    /// </summary>
    public string TurnOffTooltip => StartupEntry is { } entry
        ? $"Stops the startup entry \"{entry.DisplayName}\" launching when you sign in. Reversible — " +
          "Ballast moves it into a store it owns rather than deleting it, so you can switch it back " +
          "on at any time from the Startup page."
        : "Reversible. Ballast moves the entry into a store it owns rather than deleting it, so you " +
          "can switch it back on at any time from the Startup page.";

    /// <summary>Opens File Explorer with this finding's file selected.</summary>
    [RelayCommand]
    private void Reveal() => _page.Reveal(this);

    /// <summary>Asks Windows Defender to scan this finding's path.</summary>
    [RelayCommand]
    private Task ScanWithDefenderAsync() => _page.ScanWithDefenderAsync(this);

    /// <summary>Turns off the startup entry this finding is about, reversibly.</summary>
    [RelayCommand]
    private Task TurnOffStartupEntryAsync() => _page.TurnOffStartupEntryAsync(this);

    /// <summary>
    /// Binds this finding to a startup entry so the reversible turn-off action can be offered.
    /// </summary>
    /// <remarks>
    /// Called only when the match back to a startup entry was unambiguous. An entry that is already
    /// off, or that <see cref="StartupToggleService.CanToggle"/> refuses, keeps the button hidden
    /// and says why in <see cref="ActionNote"/> rather than offering a button that cannot work.
    /// </remarks>
    internal void AttachStartupEntry(StartupEntry entry)
    {
        StartupEntry = entry;

        if (!entry.IsEnabled)
        {
            ActionNote = "This startup entry is already switched off.";
            return;
        }

        if (!AppRoot.Services.StartupToggle.CanToggle(entry, out string? reason))
        {
            ActionNote = reason ?? "This startup entry cannot be changed from here.";
            return;
        }

        CanTurnOffStartupEntry = true;
    }
}

/// <summary>
/// One severity band and the findings in it. Grouping is done once, in the view model, so the page
/// renders the order it is given instead of sorting at bind time.
/// </summary>
public sealed class SecurityFindingGroupViewModel
{
    /// <summary>Groups <paramref name="findings"/>, all of which share <paramref name="severity"/>.</summary>
    public SecurityFindingGroupViewModel(
        FindingSeverity severity,
        IReadOnlyList<SecurityFindingViewModel> findings)
    {
        Severity = severity;
        Findings = findings;
    }

    /// <summary>The band these findings share.</summary>
    public FindingSeverity Severity { get; }

    /// <summary>The findings, in the order the auditor produced them.</summary>
    public IReadOnlyList<SecurityFindingViewModel> Findings { get; }

    /// <summary>
    /// Band label. Deliberately about attention rather than danger: "High" on its own reads as a
    /// verdict, and none of these checks is entitled to one.
    /// </summary>
    public string Label => Severity switch
    {
        FindingSeverity.High => "Worth checking first",
        FindingSeverity.Medium => "Worth checking",
        FindingSeverity.Low => "Worth a look",
        _ => "For information",
    };

    /// <summary>Footnote under the band.</summary>
    public string CountText => Findings.Count == 1
        ? "1 item in this group."
        : $"{Findings.Count:N0} items in this group.";
}

/// <summary>One rule, listed under "What was checked" so the audit is inspectable.</summary>
public sealed class SecurityCheckViewModel
{
    /// <summary>Copies the parts of <paramref name="rule"/> that are worth showing.</summary>
    public SecurityCheckViewModel(ISecurityRule rule)
    {
        RuleId = rule.RuleId;
        Name = rule.Name;
        Rationale = rule.Rationale;
    }

    /// <summary>Stable identifier, matching the one printed on each finding.</summary>
    public string RuleId { get; }

    /// <summary>Short name of the check.</summary>
    public string Name { get; }

    /// <summary>Why the rule exists and what it deliberately does not flag.</summary>
    public string Rationale { get; }
}

/// <summary>
/// The Security page.
/// </summary>
/// <remarks>
/// <para>
/// <b>This page is not an antivirus and is not allowed to imply that it is.</b> It shows two things,
/// in this order and for that reason: what Windows reports about the antivirus actually protecting
/// this PC, and then a set of structural checks Ballast ran itself. The real antivirus comes first
/// because it is the primary defence; Ballast is a second opinion about things an antivirus does not
/// look at, such as an unsigned program that has quietly added itself to startup.
/// </para>
/// <para>
/// Nothing here quarantines, deletes or repairs. Findings are reported and the user acts. The only
/// action that changes anything at all is switching off a startup entry, and that goes through the
/// existing <see cref="StartupToggleService"/>, which <em>moves</em> the entry rather than deleting
/// it and is therefore reversible.
/// </para>
/// <para>
/// False positives are the risk that matters. A scanner that cries wolf on a legitimate program
/// teaches the user to ignore it, and this app can delete files. So wherever this page cannot tell —
/// an ambiguous startup match, an antivirus state that could not be read — it says so and offers
/// nothing, rather than guessing.
/// </para>
/// </remarks>
public sealed partial class SecurityViewModel : ScanViewModelBase
{
    /// <summary>Severity bands, highest first. The page renders them in this order.</summary>
    private static readonly FindingSeverity[] _bands =
    [
        FindingSeverity.High,
        FindingSeverity.Medium,
        FindingSeverity.Low,
        FindingSeverity.Info,
    ];

    /// <summary>How far back the Defender history summary looks. Matches the Core default.</summary>
    private const int DetectionWindowDays = 30;

    private readonly SecurityAuditor _auditor = new();
    private readonly DefenderStatus _defender = new();

    /// <summary>Seeds the resting copy; the page runs <see cref="RunChecksCommand"/> when it appears.</summary>
    public SecurityViewModel() => StatusText = "Ready to run the checks.";

    // ===================================================================== findings

    /// <summary>Findings grouped by severity, highest band first.</summary>
    public ObservableCollection<SecurityFindingGroupViewModel> Groups { get; } = [];

    /// <summary>Every rule the auditor ran, for the "What was checked" list.</summary>
    public ObservableCollection<SecurityCheckViewModel> Checks { get; } = [];

    /// <summary>
    /// True only when the last run got all the way through every rule.
    /// </summary>
    /// <remarks>
    /// The empty state hangs off this rather than off "a run happened", and the difference is not
    /// cosmetic. A run that was cancelled, or that fell over, also ends with zero findings — and
    /// showing "Nothing unusual found" for it would turn a failure into an all-clear, which is the
    /// worst thing this page could do. When the checks do not finish, the page says so and shows no
    /// verdict at all.
    /// </remarks>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _lastRunCompleted;

    /// <summary>Number of findings from the last completed run.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    [NotifyPropertyChangedFor(nameof(ShowFindings))]
    private int _findingCount;

    /// <summary>True when a run that actually finished turned up nothing.</summary>
    public bool ShowEmptyState => LastRunCompleted && FindingCount == 0;

    /// <summary>True when there is at least one finding to show.</summary>
    public bool ShowFindings => FindingCount > 0;

    /// <summary>
    /// The empty state's headline. Not "you are protected", and not a tick: the checks came back
    /// quiet, which is a different and much smaller claim.
    /// </summary>
    public string EmptyStateTitle => "Nothing unusual found";

    /// <summary>The sentence that stops the empty state being read as an all-clear.</summary>
    public string EmptyStateBody =>
        "This is a set of structural checks — unsigned programs starting with Windows, autostart " +
        "entries running from unusual places, and similar. It is not a virus scan. Detecting malware " +
        "is your antivirus's job, and it keeps doing it whether or not Ballast is open.";

    /// <summary>
    /// Footnote under the findings. Says out loud that a normal PC produces findings here, because
    /// a user who reads a finding as an accusation is a user who will start ignoring them.
    /// </summary>
    public string FindingsFootnote =>
        "These are observations, not verdicts. A perfectly ordinary PC will show some of them — " +
        "plenty of small legitimate programs are unsigned, and unusual is not the same as harmful. " +
        "Ballast never quarantines, deletes or repairs anything it lists here.";

    /// <summary>Footnote under the "What was checked" list.</summary>
    public string ChecksFootnote =>
        "Every check Ballast ran, and what each one deliberately leaves alone. Ballast has no " +
        "signature database and does not try to identify known malware; that duplicates Windows " +
        "Defender badly and a stale list would be worse than none.";

    /// <summary>Whether the "What was checked" list is showing.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ChecksGlyph))]
    [NotifyPropertyChangedFor(nameof(ChecksToggleText))]
    private bool _checksExpanded;

    /// <summary>Chevron for the disclosure button.</summary>
    public string ChecksGlyph => ChecksExpanded ? Glyphs.ChevronUp : Glyphs.ChevronDown;

    /// <summary>Label for the disclosure button.</summary>
    public string ChecksToggleText => ChecksExpanded ? "Hide what was checked" : "What was checked";

    // ===================================================================== defender card

    /// <summary>The card's headline sentence about the antivirus protecting this PC.</summary>
    [ObservableProperty]
    private string _antivirusStateText = "Reading this PC's antivirus state...";

    /// <summary>The qualifying sentence under the headline. May be empty.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAntivirusStateNote))]
    private string _antivirusStateNote = string.Empty;

    /// <summary>True when there is a qualifying sentence to show.</summary>
    public bool HasAntivirusStateNote => AntivirusStateNote.Length > 0;

    /// <summary>When Defender's security intelligence was last updated.</summary>
    [ObservableProperty]
    private string _signatureText = "Not known yet";

    /// <summary>When Defender last finished a scan.</summary>
    [ObservableProperty]
    private string _lastScanText = "Not known yet";

    /// <summary>A count of what Defender logged recently, shown only when it logged something.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRecentDetections))]
    private string _recentDetectionsText = string.Empty;

    /// <summary>True when Defender's recent history is worth pointing at.</summary>
    public bool HasRecentDetections => RecentDetectionsText.Length > 0;

    /// <summary>Set while a Defender scan is being started, so the button cannot be double-fired.</summary>
    [ObservableProperty]
    private bool _isStartingDefenderScan;

    /// <summary>Result of the last "Run a quick scan" press. Empty until one is pressed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasDefenderScanNote))]
    private string _defenderScanNote = string.Empty;

    /// <summary>True once there is something to say about the quick scan.</summary>
    public bool HasDefenderScanNote => DefenderScanNote.Length > 0;

    /// <summary>Standing explanation of what this card is and is not.</summary>
    public string AntivirusFootnote =>
        "Read from Windows, never changed. Ballast is not an antivirus and does not try to be one — " +
        "this card is here because your antivirus is the thing that actually detects malware, and " +
        "it should be the first thing you look at on this page.";

    // ===================================================================== commands

    /// <summary>
    /// Reads the antivirus state, then runs Ballast's own checks.
    /// </summary>
    /// <remarks>
    /// Everything on this path is read-only: the registry, the uninstall keys, Authenticode
    /// signatures, and one PowerShell query to Windows. Nothing here can change or remove anything.
    /// </remarks>
    [RelayCommand]
    private async Task RunChecksAsync()
    {
        if (IsBusy) return;

        // The wording sets an expectation on purpose. Reading logon-triggered scheduled tasks costs
        // a multi-second schtasks.exe round trip, and a security audit that skipped them would miss
        // one of the main places persistence actually lives — so the cost is paid and explained
        // rather than avoided.
        CancellationToken ct = BeginOperation(
            "Running the checks. Reading scheduled tasks takes a few seconds.");

        // Taken down for the duration. Until a run gets all the way to the end, this page is not
        // entitled to say that nothing was found.
        LastRunCompleted = false;

        try
        {
            // Listed before the run, not after it: if the checks fail, "what was checked" is the
            // one part of the page that can still be true, and it is what makes the failure legible.
            LoadChecks();

            // Started alongside the audit rather than in front of it. Reading Defender's state is a
            // PowerShell round-trip that Core bounds at thirty seconds, and making the findings wait
            // behind that worst case would be paying for the card's position on the page with the
            // whole page's responsiveness. It cannot fault - see RefreshAntivirusCardAsync - so
            // leaving it in flight if the audit throws is safe.
            Task antivirus = RefreshAntivirusCardAsync(ct);

            IProgress<ScanProgress> progress = CreateProgress(ApplyProgress);

            // The two halves of RunAsync, taken separately so this page can keep the context. The
            // reason is the startup action below: matching a finding back to an entry against the
            // very list the rules were evaluated on is exact, whereas a second scan afterwards could
            // legitimately disagree with the one the finding came from.
            SecurityScanContext context = await _auditor.BuildContextAsync(progress, ct);
            IReadOnlyList<SecurityFinding> findings = await _auditor.RunRulesAsync(context, progress, ct);

            List<SecurityFindingViewModel> rows = Rebuild(findings);
            ResolveStartupEntries(rows, context.StartupEntries);

            await antivirus;

            // Last, and only on this path: every rule ran to completion, so what the page shows now
            // is a real result rather than however far it happened to get.
            LastRunCompleted = true;
            StatusText = Summarise(findings.Count);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Stopped before the checks finished, so this is not a result. Nothing was changed.";
        }
        catch (Exception ex)
        {
            // A failed check is a failed check, not a clean result. Say which one it was, and leave
            // LastRunCompleted false so the empty state cannot read the failure as an all-clear.
            AppLog.Write("The security checks could not be completed.", ex);
            StatusText = $"The checks could not be completed, so this is not a result: {ex.Message}";
        }
        finally
        {
            EndOperation();
        }
    }

    /// <summary>Flips the "What was checked" disclosure.</summary>
    [RelayCommand]
    private void ToggleChecks() => ChecksExpanded = !ChecksExpanded;

    /// <summary>
    /// Asks Windows Defender to start a quick scan.
    /// </summary>
    /// <remarks>
    /// This starts something Defender owns and then stops. The scan runs in Defender, the result
    /// appears in Windows Security, and Ballast does not follow it, report on it, or act on it.
    /// </remarks>
    [RelayCommand]
    private async Task RunQuickScanAsync()
    {
        if (IsStartingDefenderScan)
        {
            DefenderScanNote = "Ballast is already starting a Defender scan. Try again in a moment.";
            return;
        }

        IsStartingDefenderScan = true;

        try
        {
            // Not tied to the page's scan token: a quick scan belongs to Defender once it has
            // started, and pressing Stop on Ballast's own checks must not appear to call it back.
            bool started = await _defender.StartScanAsync(null, quickScan: true, CancellationToken.None);

            DefenderScanNote = started
                ? "Windows Defender has started a quick scan. It runs in the background and reports " +
                  "in Windows Security, not here."
                : "Windows Defender did not start a scan. It may be unavailable on this PC — " +
                  "Windows Security will say.";

            AppLog.Write(started
                ? "Started a Windows Defender quick scan from the Security page."
                : "Windows Defender declined to start a quick scan from the Security page.");
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not start a Windows Defender quick scan.", ex);
            DefenderScanNote = $"Could not start the scan: {ex.Message}";
        }
        finally
        {
            IsStartingDefenderScan = false;
        }
    }

    /// <summary>Opens Windows Security, which is where antivirus results actually live.</summary>
    [RelayCommand]
    private void OpenWindowsSecurity()
    {
        try
        {
            Process.Start(new ProcessStartInfo("windowsdefender:") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not open Windows Security.", ex);
            DefenderScanNote = "Could not open Windows Security. It is in Start under that name.";
        }
    }

    // ===================================================================== row actions

    /// <summary>Shows a finding's file in File Explorer. Reads nothing, changes nothing.</summary>
    internal void Reveal(SecurityFindingViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (row.TargetPath is not { Length: > 0 } path) return;

        try
        {
            // /select needs the path quoted: Program Files would otherwise arrive as two arguments.
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not reveal {path} in Explorer.", ex);
            row.ActionNote = "Could not open File Explorer there.";
        }
    }

    /// <summary>
    /// Hands one path to Windows Defender.
    /// </summary>
    /// <remarks>
    /// This is the honest shape of "check this file": the component that is actually entitled to a
    /// verdict gets asked for one, and whatever it decides to do about the file is its decision under
    /// its own settings. Ballast does not receive the result and never acts on it.
    /// </remarks>
    internal async Task ScanWithDefenderAsync(SecurityFindingViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (row.TargetPath is not { Length: > 0 } path) return;

        if (IsStartingDefenderScan)
        {
            // One at a time, and said out loud. A button that quietly does nothing is worse than one
            // that explains itself, particularly on a page about trusting what the app tells you.
            row.ActionNote = "Ballast is already starting a Defender scan. Try again in a moment.";
            return;
        }

        IsStartingDefenderScan = true;

        try
        {
            bool started = await _defender.StartScanAsync(path, quickScan: false, CancellationToken.None);

            row.ActionNote = started
                ? "Windows Defender has been asked to scan this path. Its answer appears in Windows " +
                  "Security, not here."
                : "Windows Defender did not start that scan. The file may have gone, or Defender may " +
                  "be unavailable on this PC.";

            AppLog.Write(started
                ? $"Asked Windows Defender to scan '{path}'."
                : $"Windows Defender declined to scan '{path}'.");
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not ask Windows Defender to scan '{path}'.", ex);
            row.ActionNote = $"Could not start that scan: {ex.Message}";
        }
        finally
        {
            IsStartingDefenderScan = false;
        }
    }

    /// <summary>
    /// Switches off the startup entry behind a finding, reversibly.
    /// </summary>
    /// <remarks>
    /// The one action on this page that changes anything. It re-asks
    /// <see cref="StartupToggleService.CanToggle"/> immediately before acting rather than trusting
    /// the check made when the button appeared — the same "a scan result is input, not permission"
    /// rule the deletion paths follow — and every outcome, including a refusal, is logged.
    /// </remarks>
    internal async Task TurnOffStartupEntryAsync(SecurityFindingViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (row.StartupEntry is not { } entry) return;
        if (!row.CanTurnOffStartupEntry) return;

        StartupToggleService toggle = AppRoot.Services.StartupToggle;

        if (!toggle.CanToggle(entry, out string? reason))
        {
            row.CanTurnOffStartupEntry = false;
            row.ActionNote = reason ?? "That startup entry cannot be changed.";
            AppLog.Write($"Refused to turn off startup entry '{entry.Name}' from Security: {row.ActionNote}");
            return;
        }

        // Taken down before the await so a second press cannot land on the same entry.
        row.CanTurnOffStartupEntry = false;

        try
        {
            await toggle.SetEnabledAsync(entry, false);

            row.ActionNote =
                $"{entry.DisplayName} will no longer launch when you sign in. Ballast kept a copy, " +
                "so you can switch it back on from the Startup page.";
            AppLog.Write($"Turned off startup entry '{entry.Name}' from the Security page.");
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not turn off startup entry '{entry.Name}' from Security.", ex);
            row.ActionNote = $"Could not switch it off: {ex.Message}";
            row.CanTurnOffStartupEntry = true;
        }
    }

    // ===================================================================== internals

    private List<SecurityFindingViewModel> Rebuild(IReadOnlyList<SecurityFinding> findings)
    {
        Groups.Clear();

        List<SecurityFindingViewModel> all = [];

        foreach (FindingSeverity band in _bands)
        {
            List<SecurityFindingViewModel> rows =
            [
                .. findings
                    .Where(f => f.Severity == band)
                    .Select(f => new SecurityFindingViewModel(this, f)),
            ];

            if (rows.Count == 0) continue;

            Groups.Add(new SecurityFindingGroupViewModel(band, rows));
            all.AddRange(rows);
        }

        FindingCount = all.Count;
        return all;
    }

    private void LoadChecks()
    {
        if (Checks.Count > 0) return; // the rule set does not change while the app is running

        try
        {
            foreach (ISecurityRule rule in _auditor.Rules)
                Checks.Add(new SecurityCheckViewModel(rule));
        }
        catch (Exception ex)
        {
            // The list is an explanation of the audit, not part of it. Losing it must not turn a
            // completed run into a failed one.
            AppLog.Write("Could not list the security rules for the 'What was checked' panel.", ex);
        }
    }

    /// <summary>
    /// Works out which findings can offer the reversible startup turn-off, and refuses to guess.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <see cref="SecurityFinding"/> carries a path, not an entry, so the entry has to be found
    /// again here. The match is exact — the entry's resolved executable path equals the finding's
    /// target path — and it is only accepted when <b>exactly one</b> entry matches. Zero matches or
    /// several means the button would be acting on something other than what the finding named, and
    /// the rule everywhere else in this app is that not being able to tell means not touching it.
    /// </para>
    /// <para>
    /// No fuzzy fallback, deliberately. A rule whose target path is a payload rather than the
    /// autostart binary — the LOLBin rule can do this — will simply not offer the button, and that
    /// is the right trade: the finding is still shown, still explains itself and still carries its
    /// own recommendation, whereas substring-matching a command line to decide which entry to switch
    /// off would be exactly the guessing this feature is not allowed to do. The entry that was
    /// matched is named in the button's tooltip either way, so the user can check before pressing it.
    /// </para>
    /// <para>
    /// The list comes from the audit's own context, which already includes logon-triggered scheduled
    /// tasks and is already deduplicated. Re-scanning here instead would risk matching a finding
    /// against a machine state that is not the one it was produced from.
    /// </para>
    /// </remarks>
    private static void ResolveStartupEntries(
        IReadOnlyList<SecurityFindingViewModel> rows,
        IReadOnlyList<StartupEntry> entries)
    {
        foreach (SecurityFindingViewModel row in rows)
        {
            if (!row.Finding.CanDisableStartupEntry || !row.HasTargetPath) continue;

            string? path = row.TargetPath;
            if (path is null) continue;

            StartupEntry? single = null;
            bool ambiguous = false;

            foreach (StartupEntry entry in entries)
            {
                if (!string.Equals(entry.ExecutablePath, path, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (single is not null)
                {
                    ambiguous = true;
                    break;
                }

                single = entry;
            }

            if (ambiguous || single is null) continue;

            row.AttachStartupEntry(single);
        }
    }

    private static string Summarise(int count) => count switch
    {
        0 => "Nothing unusual found.",
        1 => "1 thing worth a look.",
        _ => $"{count:N0} things worth a look.",
    };

    // ============================================================ the Windows Defender adapter

    /// <summary>
    /// Fills in the antivirus card from what Windows reports.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A null snapshot means <em>could not be determined</em>, and that is exactly what the card
    /// then says. It must never fall back to a reassuring default: a green state Ballast has not
    /// observed is the single most damaging thing this page could show, because it would talk
    /// somebody out of checking a real problem.
    /// </para>
    /// <para>
    /// Equally, a third-party antivirus being the active provider is not "protection is off". Core
    /// models that honestly — <see cref="DefenderSnapshot.IsActiveProvider"/> is itself nullable, so
    /// there are three answers here and not two — and the card keeps all three. False is not read as
    /// "unprotected" and null is not read as anything at all.
    /// </para>
    /// <para>
    /// Never throws, including on cancellation, so the caller can leave it in flight while the audit
    /// runs without risking an unobserved fault. A cancelled read leaves the card exactly as it was
    /// rather than overwriting a good answer with "not known".
    /// </para>
    /// </remarks>
    private async Task RefreshAntivirusCardAsync(CancellationToken ct)
    {
        try
        {
            DefenderSnapshot? snapshot = await _defender.GetAsync(ct);

            if (snapshot is null)
            {
                ShowAntivirusUnknown();
                return;
            }

            ApplyProviderState(snapshot);

            SignatureText = DescribeSignatures(snapshot);
            LastScanText = DescribeLastScan(snapshot);

            await RefreshRecentDetectionsAsync(ct);
        }
        catch (OperationCanceledException)
        {
            // A superseded run. Leaving the card untouched is right: the values on screen came from
            // a read that did finish, and replacing them with "not known" would be a downgrade
            // caused purely by the user pressing Stop.
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not read the Windows Defender status.", ex);
            ShowAntivirusUnknown();
        }
    }

    /// <summary>
    /// Says which program is protecting the PC, in the three-valued way Windows actually answers.
    /// </summary>
    /// <remarks>
    /// The order of these branches is the whole point. Defender not being the active provider is
    /// overwhelmingly because another antivirus is doing the job, and reporting that as an absence
    /// of protection is how a maintenance app frightens somebody over a perfectly healthy machine.
    /// So the third-party name is checked before anything is said about Defender being inactive, and
    /// where Windows genuinely did not say, the card says nothing rather than filling in the blank.
    /// </remarks>
    private void ApplyProviderState(DefenderSnapshot snapshot)
    {
        if (snapshot.ThirdPartyProviderName is { Length: > 0 } thirdParty &&
            snapshot.IsActiveProvider is not true)
        {
            AntivirusStateText = $"{thirdParty} is the antivirus protecting this PC.";
            AntivirusStateNote =
                "Microsoft Defender steps aside when another antivirus is in charge, which is a " +
                "normal and healthy state. Ballast cannot read another vendor's settings, so open " +
                $"{thirdParty} itself to check them.";
            return;
        }

        switch (snapshot.IsActiveProvider)
        {
            case true:
                AntivirusStateText = "Microsoft Defender is the antivirus protecting this PC.";
                AntivirusStateNote = snapshot.RealTimeProtectionEnabled switch
                {
                    true => string.Empty,
                    false => "Windows reports real-time protection as off. Worth switching back on " +
                             "in Windows Security unless you turned it off deliberately.",
                    null => "Windows did not report whether real-time protection is on.",
                };
                break;

            case false:
                AntivirusStateText = snapshot.RunningMode is DefenderRunningMode.NotRunning
                    ? "Windows reports that Microsoft Defender is not running."
                    : "Microsoft Defender is standing aside for another security product.";

                AntivirusStateNote =
                    "Ballast could not see which program is protecting this PC instead. That does " +
                    "not mean there is none — Windows does not always list them. Open Windows " +
                    "Security to see the real answer.";
                break;

            default:
                ShowAntivirusUnknown();
                break;
        }
    }

    /// <summary>The honest default for everything on this card. Deliberately not reassuring.</summary>
    private void ShowAntivirusUnknown()
    {
        AntivirusStateText = "Ballast could not read this PC's antivirus state.";
        AntivirusStateNote =
            "That is a limit of what Ballast can see, not a finding about your PC. Open Windows " +
            "Security to check it directly.";
        SignatureText = "Not known";
        LastScanText = "Not known";
        RecentDetectionsText = string.Empty;
    }

    /// <summary>
    /// How old Defender's security intelligence is, preferring the timestamp and falling back to the
    /// age in days. <c>SignaturesOutOfDate</c> is quoted as Defender's own opinion, not restated as
    /// Ballast's.
    /// </summary>
    private static string DescribeSignatures(DefenderSnapshot snapshot)
    {
        string age = snapshot.SignatureLastUpdatedUtc is { } updated
            ? Ago(updated)
            : snapshot.SignatureAgeDays is { } days
                ? Plural(days, "day") + " old"
                : "Not known";

        return snapshot.SignaturesOutOfDate is true
            ? age + "  -  Defender reports these as out of date."
            : age;
    }

    /// <summary>
    /// The more recent of Defender's two recorded scans, named so the line is unambiguous.
    /// "No scan recorded" is a fact about Defender's own history, not a judgement about the PC.
    /// </summary>
    private static string DescribeLastScan(DefenderSnapshot snapshot)
    {
        DateTimeOffset? quick = snapshot.LastQuickScanUtc;
        DateTimeOffset? full = snapshot.LastFullScanUtc;

        if (quick is null && full is null) return "No scan recorded";

        bool fullIsNewer = full is { } f && (quick is not { } q || f > q);
        DateTimeOffset latest = fullIsNewer ? full!.Value : quick!.Value;

        return $"{(fullIsNewer ? "Full scan" : "Quick scan")}, {Ago(latest)}";
    }

    /// <summary>
    /// Summarises Defender's recent history as a count and a pointer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the count is shown, on purpose. These are Defender's findings, in Defender's vocabulary,
    /// about things Defender has usually already dealt with. Repeating them here would put words
    /// like "trojan" on a Ballast page as though Ballast had concluded something, and would invite a
    /// user to act on a file that was quarantined a fortnight ago. The count plus a pointer is the
    /// most this page is entitled to say.
    /// </para>
    /// <para>
    /// An empty list from Core means "nothing recorded" <em>or</em> "could not read" — deliberately
    /// indistinguishable. So an empty list draws no line at all rather than a reassuring "0 items",
    /// which would be a claim neither Core nor this page can support.
    /// </para>
    /// </remarks>
    private async Task RefreshRecentDetectionsAsync(CancellationToken ct)
    {
        try
        {
            IReadOnlyList<DefenderDetection> detections =
                await _defender.GetRecentDetectionsAsync(DetectionWindowDays, ct);

            RecentDetectionsText = detections.Count switch
            {
                0 => string.Empty,
                1 => $"Windows Defender's own history has 1 entry from the last {DetectionWindowDays} " +
                     "days. Open Windows Security to see what it was and what Defender did about it.",
                _ => $"Windows Defender's own history has {detections.Count:N0} entries from the last " +
                     $"{DetectionWindowDays} days. Open Windows Security to see what they were and " +
                     "what Defender did about them.",
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not read the Windows Defender detection history.", ex);
            RecentDetectionsText = string.Empty;
        }
    }

    /// <summary>Relative age plus the absolute timestamp, because "8 days ago" alone invites a squint.</summary>
    private static string Ago(DateTimeOffset? when)
    {
        if (when is not { } value) return "Not known";

        TimeSpan age = DateTimeOffset.Now - value;

        // A machine whose clock has drifted forward would otherwise be told its signatures were
        // updated in the future, which reads as a bug in Ballast rather than a fact about the PC.
        if (age < TimeSpan.Zero) age = TimeSpan.Zero;

        string relative = age.TotalMinutes switch
        {
            < 90 => "less than an hour ago",
            < 36 * 60 => Plural((int)Math.Round(age.TotalHours), "hour") + " ago",
            _ => Plural((int)Math.Round(age.TotalDays), "day") + " ago",
        };

        return $"{relative}  -  {value.LocalDateTime:d MMM yyyy, HH:mm}";
    }

    private static string Plural(int count, string noun) =>
        count == 1 ? $"1 {noun}" : $"{count:N0} {noun}s";
}
