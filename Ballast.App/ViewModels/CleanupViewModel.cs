using System.Collections.ObjectModel;
using System.Text;
using Ballast.Core.Models;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>
/// The Cleanup page. Owns the scan results grouped by <see cref="JunkCategory"/> and the
/// deletion pass.
/// </summary>
/// <remarks>
/// Scanning and deleting are strictly separate: <see cref="ScanCommand"/> only reads, and
/// <see cref="CleanAsync"/> is invoked by the view <em>after</em> the user confirms a
/// <c>ContentDialog</c> that spells out exactly what is about to go.
/// </remarks>
public sealed partial class CleanupViewModel : ScanViewModelBase
{
    /// <summary>Creates the (empty) category groups in a stable display order.</summary>
    public CleanupViewModel()
    {
        foreach (JunkCategory category in Enum.GetValues<JunkCategory>())
        {
            var group = new JunkCategoryViewModel(category);
            group.SelectionChanged += OnGroupSelectionChanged;
            Categories.Add(group);
        }

        // CanClean folds in IsBusy, which lives on the base class, so re-raise it by hand.
        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(IsBusy)) OnPropertyChanged(nameof(CanClean));
        };

        // Initializer moved here from the field: a partial property cannot carry one.
        LastCleanSummary = string.Empty;

        StatusText = "Nothing scanned yet.";
    }

    /// <summary>One group per category. Groups with no items hide themselves in the view.</summary>
    public ObservableCollection<JunkCategoryViewModel> Categories { get; } = [];

    /// <summary>Paths the scanners could not read. Surfaced as a footnote, not an error.</summary>
    public ObservableCollection<string> SkippedPaths { get; } = [];

    /// <summary>Total bytes found across every category.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TotalDisplay))]
    private long _totalBytes;

    /// <summary>Bytes the current selection would reclaim.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedDisplay))]
    [NotifyPropertyChangedFor(nameof(ReclaimLabel))]
    [NotifyPropertyChangedFor(nameof(CanClean))]
    private long _selectedBytes;

    /// <summary>How many rows are ticked.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectionSummary))]
    [NotifyPropertyChangedFor(nameof(CanClean))]
    private int _selectedCount;

    /// <summary>True once a scan has completed at least once.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _hasScanned;

    /// <summary>True when the last scan produced at least one item.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _hasResults;

    /// <summary>Set after a clean pass; the view shows it in the footer.</summary>
    [ObservableProperty]
    private string _lastCleanSummary;

    /// <summary>Formatted grand total.</summary>
    public string TotalDisplay => ByteFormatter.Format(TotalBytes);

    /// <summary>Formatted selected total.</summary>
    public string SelectedDisplay => ByteFormatter.Format(SelectedBytes);

    /// <summary>The sticky footer's headline, e.g. "Reclaim 3.4 GB".</summary>
    public string ReclaimLabel => SelectedBytes > 0
        ? $"Reclaim {ByteFormatter.Format(SelectedBytes)}"
        : "Nothing selected";

    /// <summary>"412 items selected".</summary>
    public string SelectionSummary => SelectedCount == 1
        ? "1 item selected"
        : $"{SelectedCount:N0} items selected";

    /// <summary>Gate for the Clean button. Never true while an operation is running.</summary>
    public bool CanClean => !IsBusy && SelectedCount > 0 && SelectedBytes >= 0;

    /// <summary>True when a scan finished and found nothing.</summary>
    public bool ShowEmptyState => HasScanned && !HasResults;

    /// <summary>Categories that actually have something in them.</summary>
    public IEnumerable<JunkCategoryViewModel> PopulatedCategories =>
        Categories.Where(c => c.HasItems);

    /// <summary>
    /// Read-only pass over every junk source. Never deletes; the worst it can do is fail to read
    /// a folder, which lands in <see cref="SkippedPaths"/>.
    /// </summary>
    [RelayCommand]
    private async Task ScanAsync()
    {
        if (IsBusy) return;

        CancellationToken ct = BeginOperation("Scanning...");
        IProgress<ScanProgress> progress = CreateProgress(ApplyProgress);

        try
        {
            ScanResult result = await Task.Run(
                () => AppRoot.Services.ScanCoordinator.ScanAllAsync(progress, ct), ct);

            Apply(result);

            StatusText = result.Count == 0
                ? "Nothing to clean. Your drive is already tidy."
                : $"Found {ByteFormatter.Format(result.TotalBytes)} across {result.Count:N0} items.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Junk scan failed.", ex);
            StatusText = $"Scan failed: {ex.Message}";
        }
        finally
        {
            HasScanned = true;
            EndOperation();
            OnPropertyChanged(nameof(CanClean));
        }
    }

    /// <summary>
    /// Builds the text the confirmation dialog shows. Called by the view before anything is
    /// deleted so the user sees the exact categories, counts and sizes.
    /// </summary>
    public string BuildConfirmationSummary()
    {
        var sb = new StringBuilder();

        foreach (JunkCategoryViewModel group in Categories)
        {
            int count = group.SelectedItems.Count();
            if (count == 0) continue;

            long bytes = group.SelectedItems.Sum(i => i.SizeBytes);
            sb.AppendLine($"{group.Title} - {count:N0} items, {ByteFormatter.Format(bytes)}");
        }

        if (sb.Length == 0) sb.AppendLine("Nothing is selected.");

        sb.AppendLine();
        sb.Append($"Total to reclaim: {ByteFormatter.Format(SelectedBytes)}");

        if (Categories.Any(c => c.ShowAdminWarning && c.SelectedItems.Any()))
        {
            sb.AppendLine();
            sb.Append("Some of these need administrator rights and will be reported as skipped.");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Deletes the selected items. Only ever called from the view once the confirmation dialog
    /// returned <c>Primary</c>. Every path is re-validated inside the Core cleaning service.
    /// </summary>
    public async Task<CleanReport?> CleanAsync()
    {
        if (IsBusy) return null;

        List<CleanupItemViewModel> rows = Categories
            .SelectMany(c => c.SelectedItems)
            .ToList();

        if (rows.Count == 0) return null;

        List<CleanupItem> payload = rows.Select(r => r.Item).ToList();

        CancellationToken ct = BeginOperation("Cleaning...");
        IProgress<ScanProgress> progress = CreateProgress(ApplyProgress);

        try
        {
            // CleaningService already does its work on a background thread.
            CleanReport report = await AppRoot.Services.Cleaner.DeleteAsync(payload, progress, ct);

            PruneDeleted(report);

            LastCleanSummary = report.Failures.Count == 0
                ? $"Reclaimed {ByteFormatter.Format(report.BytesFreed)} from {report.ItemsDeleted:N0} items."
                : $"Reclaimed {ByteFormatter.Format(report.BytesFreed)}; {report.Failures.Count:N0} could not be removed.";

            StatusText = LastCleanSummary;
            return report;
        }
        catch (OperationCanceledException)
        {
            StatusText = "Clean cancelled. Anything already removed stays removed.";
            return null;
        }
        catch (Exception ex)
        {
            AppLog.Write("Clean pass failed.", ex);
            StatusText = $"Clean failed: {ex.Message}";
            return null;
        }
        finally
        {
            EndOperation();
            OnPropertyChanged(nameof(CanClean));
        }
    }

    private void Apply(ScanResult result)
    {
        foreach (JunkCategoryViewModel group in Categories)
        {
            group.Replace(result.Items.Where(i => i.Category == group.Category));
        }

        SkippedPaths.Clear();
        foreach (string path in result.SkippedPaths.Take(50)) SkippedPaths.Add(path);

        HasResults = result.Count > 0;
        Recalculate();
        OnPropertyChanged(nameof(PopulatedCategories));
    }

    /// <summary>
    /// Removes rows the cleaner reported as gone. Failures stay on screen so the user can see
    /// what is still there and why.
    /// </summary>
    private void PruneDeleted(CleanReport report)
    {
        HashSet<string> failed = report.Failures
            .Select(f => f.Path)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Anything that was submitted and is not in the failure list is gone; anything the user
        // never selected stays. Survivors = unselected rows + failures.
        foreach (JunkCategoryViewModel group in Categories)
        {
            HashSet<string> survivors = group.Items
                .Where(i => !i.IsSelected || failed.Contains(i.Path))
                .Select(i => i.Path)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            group.RemoveDeleted(survivors);
        }

        HasResults = Categories.Any(c => c.HasItems);
        Recalculate();
        OnPropertyChanged(nameof(PopulatedCategories));
    }

    private void OnGroupSelectionChanged() => Recalculate();

    private void Recalculate()
    {
        TotalBytes = Categories.Sum(c => c.TotalBytes);
        SelectedBytes = Categories.Sum(c => c.SelectedBytes);
        SelectedCount = Categories.Sum(c => c.SelectedItems.Count());
    }
}
