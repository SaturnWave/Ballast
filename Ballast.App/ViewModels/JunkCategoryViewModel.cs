using System.Collections.ObjectModel;
using Ballast.Core.Models;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Ballast.App.ViewModels;

/// <summary>
/// A group row on the Cleanup page: one <see cref="JunkCategory"/>, its items, the aggregate size
/// and a tri-state include/exclude checkbox that stays in sync with its children.
/// </summary>
public sealed partial class JunkCategoryViewModel : ObservableObject
{
    /// <summary>How many rows we materialise into the expanded list before collapsing the tail.</summary>
    public const int PreviewLimit = 60;

    private bool _syncing;

    /// <summary>Creates an empty group for <paramref name="category"/>.</summary>
    public JunkCategoryViewModel(JunkCategory category)
    {
        Category = category;

        // Initializer moved here from the field: a partial property cannot carry one. The group is
        // still empty, so the cascade in OnIsSelectedChanged has nothing to touch.
        IsSelected = true;
    }

    /// <summary>The category this group represents.</summary>
    public JunkCategory Category { get; }

    /// <summary>Every item the scanners attributed to this category.</summary>
    public List<CleanupItemViewModel> Items { get; } = [];

    /// <summary>The subset bound to the expanded list, capped at <see cref="PreviewLimit"/>.</summary>
    public ObservableCollection<CleanupItemViewModel> PreviewItems { get; } = [];

    /// <summary>Localised category name, e.g. "Browser Caches".</summary>
    public string Title => Category.DisplayName();

    /// <summary>The reassuring one-liner explaining what will be removed.</summary>
    public string Subtitle => Category.Description();

    /// <summary>Segoe Fluent Icons glyph for the leading tile.</summary>
    public string Glyph => Category.Glyph();

    /// <summary>
    /// Tri-state include flag. <c>true</c> = all children in, <c>false</c> = none,
    /// <c>null</c> = a mixture (the checkbox shows its indeterminate mark).
    /// </summary>
    [ObservableProperty]
    private bool? _isSelected;

    /// <summary>Whether the individual items are showing.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExpandGlyph))]
    private bool _isExpanded;

    /// <summary>Chevron direction for the expand affordance.</summary>
    public string ExpandGlyph => IsExpanded ? Glyphs.ChevronUp : Glyphs.ChevronDown;

    /// <summary>Total bytes found in this category.</summary>
    public long TotalBytes { get; private set; }

    /// <summary>Bytes the current selection would reclaim.</summary>
    public long SelectedBytes { get; private set; }

    /// <summary>Number of items found.</summary>
    public int Count => Items.Count;

    /// <summary>True when at least one item was found.</summary>
    public bool HasItems => Items.Count > 0;

    /// <summary>Formatted <see cref="TotalBytes"/>, for the trailing label.</summary>
    public string TotalDisplay => ByteFormatter.Format(TotalBytes);

    /// <summary>"128 items" / "1 item".</summary>
    public string CountDisplay => Count == 1 ? "1 item" : $"{Count:N0} items";

    /// <summary>True when anything in this category needs an elevated process to remove.</summary>
    public bool RequiresAdmin { get; private set; }

    /// <summary>Shown as a warning footnote when <see cref="RequiresAdmin"/> and we are not elevated.</summary>
    public bool ShowAdminWarning => RequiresAdmin && !Elevation.IsElevated;

    /// <summary>
    /// The card's footnote: what this category is, plus the elevation caveat when it applies.
    /// </summary>
    public string FooterText => ShowAdminWarning
        ? $"{Subtitle} Relaunch as administrator to include these."
        : Subtitle;

    /// <summary>"and 412 more" tail note when the list is capped.</summary>
    public string MoreItemsText =>
        Items.Count > PreviewLimit
            ? $"and {Items.Count - PreviewLimit:N0} more, all included in the total above"
            : string.Empty;

    /// <summary>True when the tail note should be visible.</summary>
    public bool HasMoreItems => Items.Count > PreviewLimit;

    /// <summary>Flips <see cref="IsExpanded"/>.</summary>
    [RelayCommand]
    private void ToggleExpanded() => IsExpanded = !IsExpanded;

    /// <summary>Replaces the contents of this group with <paramref name="items"/>.</summary>
    public void Replace(IEnumerable<CleanupItem> items)
    {
        Items.Clear();
        PreviewItems.Clear();

        foreach (CleanupItem item in items.OrderByDescending(i => i.SizeBytes))
        {
            var row = new CleanupItemViewModel(item, this);
            Items.Add(row);
            if (PreviewItems.Count < PreviewLimit) PreviewItems.Add(row);
        }

        RequiresAdmin = Items.Exists(i => i.RequiresAdmin);

        _syncing = true;
        IsSelected = Items.Count > 0 ? true : false;
        _syncing = false;

        Recalculate();
        RaiseShapeChanged();
    }

    /// <summary>Drops rows that were successfully deleted, keeping the failures visible.</summary>
    public void RemoveDeleted(ISet<string> stillPresentPaths)
    {
        List<CleanupItemViewModel> survivors =
            Items.Where(i => stillPresentPaths.Contains(i.Path)).ToList();

        if (survivors.Count == Items.Count) return;

        Items.Clear();
        Items.AddRange(survivors);

        PreviewItems.Clear();
        foreach (CleanupItemViewModel row in Items.Take(PreviewLimit)) PreviewItems.Add(row);

        RequiresAdmin = Items.Exists(i => i.RequiresAdmin);
        Recalculate();
        RaiseShapeChanged();
    }

    /// <summary>Called by a child row when the user toggles it.</summary>
    public void OnChildSelectionChanged()
    {
        if (_syncing) return;

        int selected = Items.Count(i => i.IsSelected);

        _syncing = true;
        IsSelected = selected == 0 ? false : selected == Items.Count ? true : null;
        _syncing = false;

        Recalculate();
    }

    /// <summary>The items the user wants removed.</summary>
    public IEnumerable<CleanupItemViewModel> SelectedItems => Items.Where(i => i.IsSelected);

    partial void OnIsSelectedChanged(bool? value)
    {
        // A null coming from the checkbox itself means "mixed"; only an explicit true/false
        // should cascade down to the children.
        if (_syncing || value is null) { Recalculate(); return; }

        _syncing = true;
        foreach (CleanupItemViewModel row in Items) row.IsSelected = value.Value;
        _syncing = false;

        Recalculate();
    }

    private void Recalculate()
    {
        TotalBytes = Items.Sum(i => i.SizeBytes);
        SelectedBytes = Items.Where(i => i.IsSelected).Sum(i => i.SizeBytes);

        OnPropertyChanged(nameof(TotalBytes));
        OnPropertyChanged(nameof(SelectedBytes));
        OnPropertyChanged(nameof(TotalDisplay));

        SelectionChanged?.Invoke();
    }

    private void RaiseShapeChanged()
    {
        OnPropertyChanged(nameof(Count));
        OnPropertyChanged(nameof(CountDisplay));
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(RequiresAdmin));
        OnPropertyChanged(nameof(ShowAdminWarning));
        OnPropertyChanged(nameof(FooterText));
        OnPropertyChanged(nameof(HasMoreItems));
        OnPropertyChanged(nameof(MoreItemsText));
    }

    /// <summary>Raised whenever the selection (and therefore the reclaimable total) changes.</summary>
    public event Action? SelectionChanged;
}
