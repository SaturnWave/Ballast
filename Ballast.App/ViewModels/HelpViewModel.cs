using System.Diagnostics;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Ballast.App.ViewModels;

/// <summary>
/// One row of the risk legend on the Help page.
///
/// <para>
/// The wording is <b>read from <see cref="DeletionRiskAssessor"/>, never retyped</b>. The legend and
/// the treemap have to say the same thing about the same colour, and a hand-written copy of five
/// sentences in XAML is a copy that will drift the first time the assessor's wording is improved.
/// </para>
/// </summary>
public sealed class RiskLevelInfo
{
    private RiskLevelInfo(DeletionRisk level)
    {
        Level = level;
        Label = DeletionRiskAssessor.ShortLabel(level);
        Description = DeletionRiskAssessor.Describe(level);
    }

    /// <summary>Builds the legend row for one level.</summary>
    public static RiskLevelInfo For(DeletionRisk level) => new(level);

    /// <summary>The level this row describes.</summary>
    public DeletionRisk Level { get; }

    /// <summary>Two or three words: <c>DeletionRiskAssessor.ShortLabel</c>.</summary>
    public string Label { get; }

    /// <summary>One plain sentence: <c>DeletionRiskAssessor.Describe</c>.</summary>
    public string Description { get; }
}

/// <summary>
/// The Help page's state, which is deliberately almost none: the page is prose, and prose belongs
/// in XAML where it can be read in place.
///
/// <para>
/// Two things cannot be hard-coded there. The five risk descriptions come from
/// <see cref="DeletionRiskAssessor"/> so the page cannot drift from the code it is describing, and
/// the log folder is a real path on this machine, with a button that opens it — a safety claim the
/// user can check is worth more than one they have to take on trust.
/// </para>
/// </summary>
public sealed partial class HelpViewModel : ObservableObject
{
    /// <summary>Level 1, red: refused outright by <see cref="SystemPathGuard"/>.</summary>
    public RiskLevelInfo SystemLevel { get; } = RiskLevelInfo.For(DeletionRisk.System);

    /// <summary>Level 2, orange.</summary>
    public RiskLevelInfo RiskyLevel { get; } = RiskLevelInfo.For(DeletionRisk.Risky);

    /// <summary>Level 3, amber — also where anything unrecognised lands.</summary>
    public RiskLevelInfo CautionLevel { get; } = RiskLevelInfo.For(DeletionRisk.Caution);

    /// <summary>Level 4, olive.</summary>
    public RiskLevelInfo ProbablySafeLevel { get; } = RiskLevelInfo.For(DeletionRisk.ProbablySafe);

    /// <summary>Level 5, green: the paths the junk allowlist already covers.</summary>
    public RiskLevelInfo SafeLevel { get; } = RiskLevelInfo.For(DeletionRisk.Safe);

    /// <summary>Where the audit log is written.</summary>
    public string LogFolder => AppLog.Folder;

    /// <summary>
    /// How this process is actually running, rather than how the manifest asked to run. Stated
    /// because the administrator section makes a claim about what is reachable, and the honest
    /// version of that claim depends on the answer.
    /// </summary>
    public string ElevationText => Elevation.IsElevated
        ? "Right now Ballast is running as administrator, so the machine-wide locations below are reachable."
        : "Right now Ballast is running as a standard user, so the machine-wide locations below are out of reach and will not appear in a scan.";

    /// <summary>
    /// The size of the cleanup allowlist, read from <see cref="PathSafety"/> rather than typed into
    /// the page, and a pointer at the Settings page where every entry is printed in full.
    /// </summary>
    public string AllowlistText =>
        $"Automatic cleaning is confined to {PathSafety.AllowedRoots.Count:N0} junk locations and nowhere else. " +
        "Settings prints the whole list, so you can read it before you press anything.";

    /// <summary>Transient confirmation or failure text under the log folder button.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasStatus))]
    private string _statusText = string.Empty;

    /// <summary>Keeps the status line out of the layout until there is something to say.</summary>
    public bool HasStatus => StatusText.Length > 0;

    /// <summary>Opens the audit log folder in Explorer.</summary>
    [RelayCommand]
    private void OpenLogFolder()
    {
        try
        {
            string folder = AppLog.EnsureFolder();
            Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
            StatusText = "Opened the log folder.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not open the log folder.", ex);
            StatusText = $"Could not open the log folder: {ex.Message}";
        }
    }
}
