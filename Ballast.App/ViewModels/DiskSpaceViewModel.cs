using System.Collections.ObjectModel;
using System.Windows.Input;
using Ballast.Core.Cleaning;
using Ballast.Core.DiskAnalysis;
using Ballast.Core.Models;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>One drive in the segmented picker.</summary>
public sealed partial class DriveOptionViewModel : ObservableObject
{
    private readonly Action<DriveOptionViewModel>? _onSelected;

    /// <summary>Wraps a <see cref="DriveSummary"/> and reports selection to the page view model.</summary>
    public DriveOptionViewModel(DriveSummary drive, Action<DriveOptionViewModel>? onSelected = null)
    {
        Drive = drive;
        _onSelected = onSelected;
    }

    /// <summary>The Core snapshot this row was built from.</summary>
    public DriveSummary Drive { get; }

    /// <summary>Path the tree scanner is pointed at.</summary>
    public string Root => Drive.RootPath;

    /// <summary>Short segment caption, e.g. "C:".</summary>
    public string Label => Drive.Name.TrimEnd('\\', '/');

    /// <summary>Label-first title, e.g. "Windows (C:)".</summary>
    public string Title => Drive.DisplayName;

    /// <summary>"312 GB of 931 GB used - 619 GB free".</summary>
    public string Caption =>
        $"{Drive.UsedDisplay} of {Drive.TotalDisplay} used  -  {Drive.FreeDisplay} free";

    /// <summary>Occupied share as a 0-100 percentage, for a ProgressBar.</summary>
    public double UsedPercent => Drive.UsedFraction * 100d;

    /// <summary>
    /// True when this looks like a cloud sync mount rather than a real disk; its capacity figures
    /// describe an account quota, so we say so instead of pretending.
    /// </summary>
    public bool IsCloudMount => Drive.IsLikelyCloudMount;

    /// <summary>Bound to the segmented control's ToggleButton.</summary>
    [ObservableProperty]
    private bool _isSelected;

    partial void OnIsSelectedChanged(bool value)
    {
        if (value) _onSelected?.Invoke(this);
    }
}

/// <summary>One segment of the drill-down trail above the map.</summary>
public sealed class BreadcrumbViewModel
{
    /// <summary>Wraps <paramref name="node"/> as a clickable crumb.</summary>
    public BreadcrumbViewModel(DirNode node, ICommand navigate, bool isLast)
    {
        Node = node;
        NavigateCommand = navigate;
        ShowSeparator = !isLast;
    }

    /// <summary>The folder this crumb jumps to.</summary>
    public DirNode Node { get; }

    /// <summary>Crumb caption. Drive roots keep their full "C:\" name, which is what they are.</summary>
    public string Name => Node.Name;

    /// <summary>The page's shared navigate command; the crumb passes its own node as the parameter.</summary>
    public ICommand NavigateCommand { get; }

    /// <summary>False on the trailing crumb, so the trail does not end in a chevron.</summary>
    public bool ShowSeparator { get; }
}

/// <summary>A "largest folder" or "largest file" row, with a bar relative to the biggest row.</summary>
public sealed partial class SizeEntryViewModel : ObservableObject
{
    private readonly Action<DirNode>? _onActivated;

    /// <summary>Projects a scanned tree node into a display row.</summary>
    public SizeEntryViewModel(DirNode node, Action<DirNode>? onActivated = null)
    {
        Node = node;
        _onActivated = onActivated;
        Name = node.Name;
        Path = node.FullPath;
        SizeBytes = node.SizeBytes;
        IsDirectory = node.IsDirectory;
    }

    /// <summary>The tree node behind the row. Never mutated.</summary>
    public DirNode Node { get; }

    /// <summary>Folder or file name.</summary>
    public string Name { get; }

    /// <summary>Full path, shown as secondary text.</summary>
    public string Path { get; }

    /// <summary>Size on disk, aggregated over the subtree for folders.</summary>
    public long SizeBytes { get; }

    /// <summary>True for folders.</summary>
    public bool IsDirectory { get; }

    /// <summary>
    /// Segoe Fluent Icons glyph. The size label is formatted in the view by
    /// <see cref="Converters.BytesToStringConverter"/> rather than duplicated here.
    /// </summary>
    public string Glyph => IsDirectory ? Glyphs.Folder : Glyphs.Page;

    /// <summary>0-100, relative to the largest row in the same list.</summary>
    [ObservableProperty]
    private double _percentOfLargest;

    /// <summary>Clicking the row drills into a folder, or selects a file for the Delete affordance.</summary>
    [RelayCommand]
    private void Activate() => _onActivated?.Invoke(Node);
}

/// <summary>
/// The Disk Space page: pick a drive, measure it, then explore the result as a nested treemap and
/// remove the one thing that turned out to be the problem.
/// </summary>
/// <remarks>
/// <para>
/// Measuring is done by <see cref="DirectoryTreeScanner"/>, which opens no write handles. The one
/// destructive path is <see cref="DeleteSelectedAsync"/>, and it is deliberately not a command: the
/// page must show a <c>ContentDialog</c> naming the item before it can be reached, and deletion
/// goes through <see cref="UserFileDeleter"/>.
/// </para>
/// <para>
/// That delete is reversible by default — the shell moves the item to the Recycle Bin — and
/// irreversible only when the caller asks for it by name. The permanent path is a parameter rather
/// than a mode precisely so it cannot be left switched on: the page passes it from one specific
/// right-click item, behind its own differently worded confirmation, and every other caller gets
/// the reversible delete without having to know the difference exists.
/// </para>
/// <para>
/// Anything <see cref="SystemPathGuard.IsProtected"/> rejects is refused here too, with the reason
/// shown next to a disabled Delete button rather than as a failure after the fact. See
/// <see cref="RefuseIfProtected"/>: the refusal is published before a confirmation is offered, not
/// after one is accepted, and that holds for both kinds of delete.
/// </para>
/// </remarks>
public sealed partial class DiskSpaceViewModel : ScanViewModelBase
{
    /// <summary>
    /// Files below this get no node of their own. It keeps a whole-drive tree small enough to hold
    /// in memory while still covering every file a "largest files" list would ever show.
    /// </summary>
    private const long FileNodeThreshold = 8L * 1000 * 1000;

    private const int TopCount = 25;

    /// <summary>Loads the drive list; measuring waits for an explicit scan.</summary>
    public DiskSpaceViewModel()
    {
        // IsBusy lives on the base class, so its generated change hook is not ours to implement.
        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(IsBusy)) OnPropertyChanged(nameof(CanDelete));
        };

        LoadDrives();
        StatusText = "Pick a drive and scan to see where the space went.";
    }

    /// <summary>The segmented drive picker's items.</summary>
    public ObservableCollection<DriveOptionViewModel> Drives { get; } = [];

    /// <summary>Biggest folders inside the folder the map is currently showing, largest first.</summary>
    public ObservableCollection<SizeEntryViewModel> LargestFolders { get; } = [];

    /// <summary>Biggest individual files inside the folder the map is currently showing.</summary>
    public ObservableCollection<SizeEntryViewModel> LargestFiles { get; } = [];

    /// <summary>The drill-down trail, root first.</summary>
    public ObservableCollection<BreadcrumbViewModel> Breadcrumbs { get; } = [];

    /// <summary>The drive currently being examined.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedDriveCaption))]
    [NotifyPropertyChangedFor(nameof(SelectedDrivePercent))]
    [NotifyPropertyChangedFor(nameof(ShowCloudWarning))]
    [NotifyPropertyChangedFor(nameof(CloudWarning))]
    private DriveOptionViewModel? _selectedDrive;

    /// <summary>
    /// The measured tree. Bound straight to the treemap's <c>Root</c>; null before the first scan.
    /// </summary>
    [ObservableProperty]
    private DirNode? _treeRoot;

    /// <summary>
    /// The folder the map is filled with. Kept in step with the treemap control in both directions:
    /// the control raises its change here, and a breadcrumb click pushes back into the control.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanGoUp))]
    [NotifyPropertyChangedFor(nameof(FoldersHeader))]
    [NotifyPropertyChangedFor(nameof(FilesHeader))]
    private DirNode? _currentNode;

    /// <summary>The tile or row the user picked, and the only thing Delete can act on.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyPropertyChangedFor(nameof(CanDelete))]
    [NotifyPropertyChangedFor(nameof(SelectionTitle))]
    [NotifyPropertyChangedFor(nameof(SelectionPath))]
    [NotifyPropertyChangedFor(nameof(SelectionSize))]
    [NotifyPropertyChangedFor(nameof(SelectionGlyph))]
    private DirNode? _selectedNode;

    /// <summary>
    /// Why the selection cannot be deleted, or empty when it can. This drives
    /// <see cref="CanDelete"/>, and is written after <see cref="SelectedNode"/>, so it has to
    /// re-raise that too or the button keeps the previous item's verdict.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasBlockedReason))]
    [NotifyPropertyChangedFor(nameof(CanDelete))]
    private string _blockedReason = string.Empty;

    /// <summary>An extra caution for a deletable-but-regrettable selection, or empty.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasRiskWarning))]
    private string _riskWarning = string.Empty;

    /// <summary>What the pointer is currently over on the map. Empty when it is over nothing.</summary>
    [ObservableProperty]
    private string _hoverText = string.Empty;

    /// <summary>True once a survey has finished.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _hasScanned;

    /// <summary>How many folders were unreadable during the last survey.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SkippedFootnote))]
    private int _skippedCount;

    /// <summary>Capacity summary for the selected drive.</summary>
    public string SelectedDriveCaption => SelectedDrive?.Caption ?? "No drive selected";

    /// <summary>Used percentage for the selected drive, 0-100.</summary>
    public double SelectedDrivePercent => SelectedDrive?.UsedPercent ?? 0d;

    /// <summary>True when the selected drive is a cloud sync mount masquerading as a disk.</summary>
    public bool ShowCloudWarning => SelectedDrive?.IsCloudMount == true;

    /// <summary>The cloud-mount caveat, spelled out rather than hinted at.</summary>
    public string CloudWarning =>
        $"{SelectedDrive?.Label ?? "This drive"} looks like a cloud sync mount. Its capacity is an " +
        "account quota, not local disk space, so freeing bytes here will not give your real disk " +
        "any room. Scanning it is also slow, because every folder is a network round trip.";

    /// <summary>True when the drill-down is somewhere below the root.</summary>
    public bool CanGoUp => CurrentNode?.Parent is not null;

    /// <summary>True when something is selected.</summary>
    public bool HasSelection => SelectedNode is not null;

    /// <summary>Gate for the Delete button: a selection, nothing in flight, nothing protected.</summary>
    public bool CanDelete => SelectedNode is not null && !IsBusy && BlockedReason.Length == 0;

    /// <summary>True when <see cref="BlockedReason"/> has something to say.</summary>
    public bool HasBlockedReason => BlockedReason.Length > 0;

    /// <summary>True when <see cref="RiskWarning"/> has something to say.</summary>
    public bool HasRiskWarning => RiskWarning.Length > 0;

    /// <summary>Selected item's name, or a resting prompt.</summary>
    public string SelectionTitle => SelectedNode?.Name ?? "Nothing selected";

    /// <summary>Selected item's full path, or a hint at how to get one.</summary>
    public string SelectionPath =>
        SelectedNode?.FullPath ?? "Click a file on the map, or right-click any tile, to select it.";

    /// <summary>Selected item's size, or empty.</summary>
    public string SelectionSize => SelectedNode?.SizeDisplay ?? string.Empty;

    /// <summary>Folder or file glyph for the selection bar.</summary>
    public string SelectionGlyph => SelectedNode is { IsDirectory: false } ? Glyphs.Page : Glyphs.Folder;

    /// <summary>Header over the largest-folders card, naming the folder it describes.</summary>
    public string FoldersHeader => Scoped("Largest folders");

    /// <summary>Header over the largest-files card, naming the folder it describes.</summary>
    public string FilesHeader => Scoped("Largest files");

    /// <summary>True when the survey found nothing worth listing.</summary>
    public bool ShowEmptyState => HasScanned && LargestFolders.Count == 0 && LargestFiles.Count == 0;

    /// <summary>Footnote under the map, explaining what it does and does not show.</summary>
    public string MapFooter =>
        "Each rectangle is one folder or file, sized by how much space it takes; nested rectangles " +
        "are what is inside it. Click a folder to go deeper, right-click anything for its menu. " +
        $"Very small items and levels past {TreemapDepth} are left out so the map stays readable.";

    /// <summary>Footnote under the largest-files card.</summary>
    public string FilesFootnote =>
        $"Files smaller than {ByteFormatter.Format(FileNodeThreshold)} are not listed individually, " +
        "though their bytes are counted in every folder total.";

    /// <summary>Footnote explaining an incomplete total.</summary>
    public string SkippedFootnote => SkippedCount == 0
        ? string.Empty
        : $"{SkippedCount:N0} folders could not be read, so these totals are a floor, not the whole truth.";

    /// <summary>Nesting levels the map draws. Matches the control's default.</summary>
    public int TreemapDepth => 3;

    /// <summary>Measures the selected drive and fills the map and the lists.</summary>
    [RelayCommand]
    private Task ScanAsync() => RunScanAsync(null);

    /// <summary>Re-reads the drive table, keeping the current selection where possible.</summary>
    [RelayCommand]
    private void RefreshDrives()
    {
        string? previous = SelectedDrive?.Root;
        LoadDrives(previous);
    }

    /// <summary>Drills the map into <paramref name="node"/>. Bound by the breadcrumbs and list rows.</summary>
    [RelayCommand]
    private void Navigate(DirNode? node)
    {
        if (node is null) return;

        if (!node.IsDirectory)
        {
            SetSelection(node);
            return;
        }

        SetCurrentNode(node);
    }

    /// <summary>Moves the map up one folder.</summary>
    [RelayCommand]
    private void GoUp()
    {
        if (CurrentNode?.Parent is { } parent) SetCurrentNode(parent);
    }

    /// <summary>
    /// Points the page at <paramref name="node"/>, rebuilding the trail and both lists. Idempotent,
    /// which is what stops the page and the treemap control from ping-ponging.
    /// </summary>
    public void SetCurrentNode(DirNode? node)
    {
        if (ReferenceEquals(CurrentNode, node)) return;

        CurrentNode = node;
        RebuildBreadcrumbs();
        RefreshLists();
    }

    /// <summary>
    /// Records the selection and asks <see cref="SystemPathGuard"/> what may be done with it, so
    /// the answer is visible before the user reaches for Delete rather than after.
    /// </summary>
    public void SetSelection(DirNode? node)
    {
        if (ReferenceEquals(SelectedNode, node)) return;

        SelectedNode = node;

        if (node is null)
        {
            BlockedReason = string.Empty;
            RiskWarning = string.Empty;
            return;
        }

        BlockedReason = SystemPathGuard.IsProtected(node.FullPath, out string? reason)
            ? reason ?? "This path is protected."
            : string.Empty;

        RiskWarning = SystemPathGuard.IsRisky(node.FullPath, out string? warning)
            ? warning ?? string.Empty
            : string.Empty;
    }

    /// <summary>
    /// Re-asks <see cref="SystemPathGuard"/> about <paramref name="node"/> and, when it refuses,
    /// publishes the reason. True means "stop, and do not ask the user anything about this item".
    /// </summary>
    /// <remarks>
    /// The page calls this <em>before</em> it opens a confirmation, so a refusal arrives instead of a
    /// dialog rather than after one. Confirming something the app was always going to reject teaches
    /// the user that these dialogs do not mean what they say, which is the one lesson a delete flow
    /// cannot afford to teach.
    /// </remarks>
    public bool RefuseIfProtected(DirNode node)
    {
        if (!SystemPathGuard.IsProtected(node.FullPath, out string? reason)) return false;

        string refusal = reason ?? "This path is protected.";
        StatusText = refusal;

        // BlockedReason is read as a caption on the selection bar, so it may only be written when
        // the refused item is the one that bar is describing.
        if (ReferenceEquals(SelectedNode, node)) BlockedReason = refusal;

        return true;
    }

    /// <summary>Reports what the pointer is over, for the line under the map.</summary>
    public void SetHover(DirNode? node) =>
        HoverText = node is null ? string.Empty : $"{node.SizeDisplay}   {node.FullPath}";

    /// <summary>
    /// Deletes the selection, then re-measures the drive so the map cannot show something that is no
    /// longer there.
    /// </summary>
    /// <param name="permanent">
    /// False routes the item through the shell to the Recycle Bin, where it stays restorable. True
    /// bypasses the bin outright: the bytes are gone, and neither this app nor Windows can bring
    /// them back. Only ever true when the user has been through the page's permanent-delete
    /// confirmation, which says exactly that.
    /// </param>
    /// <remarks>
    /// Only ever called from one of the page's confirmation dialogs. Returns null when there was
    /// nothing to do or the guard refused; otherwise the report, including per-path failures.
    /// <see cref="UserFileDeleter"/> writes the permanent case to the audit log as such, so the two
    /// kinds of delete are told apart there without this method logging anything extra.
    /// </remarks>
    public async Task<CleanReport?> DeleteSelectedAsync(bool permanent = false)
    {
        if (IsBusy || SelectedNode is not { } target) return null;

        // The guard is re-asked here rather than trusted from the UI state: the selection could
        // have been made before a path changed underneath it. This matters more on the permanent
        // path than anywhere else, because there is nothing to undo afterwards.
        if (RefuseIfProtected(target)) return null;

        string path = target.FullPath;
        string name = target.Name;
        string? resume = CurrentNode?.FullPath;

        CancellationToken ct = BeginOperation(permanent
            ? $"Permanently deleting {name}..."
            : $"Moving {name} to the Recycle Bin...");

        CleanReport report;
        try
        {
            report = await UserFileDeleter.Shared.DeleteAsync(
                [path], permanent, CreateProgress(ApplyProgress), ct);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Delete cancelled.";
            return null;
        }
        catch (Exception ex)
        {
            AppLog.Write($"{(permanent ? "Permanently deleting" : "Deleting")} {path} failed.", ex);
            StatusText = $"Could not delete {name}: {ex.Message}";
            return null;
        }
        finally
        {
            EndOperation();
        }

        string freed = ByteFormatter.Format(report.BytesFreed);

        StatusText = (report.ItemsDeleted, permanent) switch
        {
            ( > 0, true) => $"Permanently deleted {name}, freeing {freed}. It did not go to the Recycle Bin.",
            ( > 0, false) => $"Moved {name} to the Recycle Bin, freeing {freed}.",
            _ => $"{name} was not deleted.",
        };

        SetSelection(null);

        // The tree in memory is now a lie about the disk. Re-measure before showing it again.
        if (report.ItemsDeleted > 0 && SelectedDrive is not null)
            await RunScanAsync(resume);

        return report;
    }

    private async Task RunScanAsync(string? resumePath)
    {
        if (IsBusy) return;

        DriveOptionViewModel? drive = SelectedDrive;
        if (drive is null)
        {
            StatusText = "Select a drive first.";
            return;
        }

        CancellationToken ct = BeginOperation($"Measuring {drive.Label}...");
        IProgress<ScanProgress> progress = CreateProgress(ApplyProgress);

        var options = new TreeScanOptions
        {
            IncludeFiles = true,
            MinimumFileSizeBytes = FileNodeThreshold,
        };

        try
        {
            // ScanDetailedAsync already does its walking on a background thread.
            TreeScanResult result = await AppRoot.Services.TreeScanner
                .ScanDetailedAsync(drive.Root, options, progress, ct);

            SetSelection(null);
            TreeRoot = result.Root;

            // Assigning TreeRoot resets the map to the root, so the page's CurrentNode has to be
            // re-seeded here regardless of what it was.
            CurrentNode = null;
            SetCurrentNode(resumePath is null ? result.Root : DeepestExisting(result.Root, resumePath));
            SkippedCount = result.SkippedCount;

            StatusText = result.TotalBytes == 0
                ? "Nothing measurable on this drive."
                : $"Measured {ByteFormatter.Format(result.TotalBytes)} across " +
                  $"{result.FolderCount:N0} folders and {result.FileCount:N0} files.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Measurement cancelled.";
        }
        catch (Exception ex)
        {
            AppLog.Write($"Disk survey of {drive.Root} failed.", ex);
            StatusText = $"Could not measure {drive.Label}: {ex.Message}";
        }
        finally
        {
            HasScanned = true;
            EndOperation();
            OnPropertyChanged(nameof(ShowEmptyState));
        }
    }

    private void LoadDrives(string? preferredRoot = null)
    {
        Drives.Clear();

        try
        {
            foreach (DriveSummary drive in AppRoot.Services.Drives.GetFixedDrives())
                Drives.Add(new DriveOptionViewModel(drive, OnDriveSelected));
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not enumerate drives.", ex);
        }

        if (Drives.Count == 0)
        {
            SelectedDrive = null;
            StatusText = "No local drives are available to measure.";
            return;
        }

        DriveOptionViewModel target = Drives.FirstOrDefault(
            d => string.Equals(d.Root, preferredRoot, StringComparison.OrdinalIgnoreCase)) ?? Drives[0];

        target.IsSelected = true;
    }

    private void OnDriveSelected(DriveOptionViewModel option)
    {
        foreach (DriveOptionViewModel other in Drives)
        {
            if (!ReferenceEquals(other, option)) other.IsSelected = false;
        }

        SelectedDrive = option;
        SetSelection(null);
        TreeRoot = null;
        SetCurrentNode(null);
        HasScanned = false;
        SkippedCount = 0;

        StatusText = option.IsCloudMount
            ? $"{option.Label} looks like a cloud sync mount, so its capacity is an account quota, not disk space."
            : $"{option.Label} selected. Scan to see where the space went.";
    }

    private void RebuildBreadcrumbs()
    {
        Breadcrumbs.Clear();
        if (CurrentNode is null) return;

        var chain = new List<DirNode>();
        for (DirNode? node = CurrentNode; node is not null; node = node.Parent)
            chain.Add(node);

        chain.Reverse();

        for (int i = 0; i < chain.Count; i++)
            Breadcrumbs.Add(new BreadcrumbViewModel(chain[i], NavigateCommand, i == chain.Count - 1));
    }

    private void RefreshLists()
    {
        if (CurrentNode is null)
        {
            LargestFolders.Clear();
            LargestFiles.Clear();
            OnPropertyChanged(nameof(ShowEmptyState));
            return;
        }

        Fill(LargestFolders, LargestItemsFinder.LargestFolders(CurrentNode, TopCount));
        Fill(LargestFiles, LargestItemsFinder.LargestFiles(CurrentNode, TopCount));
        OnPropertyChanged(nameof(ShowEmptyState));
    }

    private void Fill(ObservableCollection<SizeEntryViewModel> target, IReadOnlyList<DirNode> nodes)
    {
        target.Clear();
        if (nodes.Count == 0) return;

        long largest = nodes.Max(n => n.SizeBytes);

        foreach (DirNode node in nodes)
        {
            target.Add(new SizeEntryViewModel(node, OnEntryActivated)
            {
                PercentOfLargest = largest > 0 ? node.SizeBytes * 100d / largest : 0d,
            });
        }
    }

    /// <summary>A list row behaves like a tile: folders drill in, files get selected.</summary>
    private void OnEntryActivated(DirNode node)
    {
        if (node.IsDirectory)
        {
            SetCurrentNode(node);
            return;
        }

        SetSelection(node);
    }

    private string Scoped(string label) =>
        CurrentNode is null || ReferenceEquals(CurrentNode, TreeRoot)
            ? label
            : $"{label} in {CurrentNode.Name}";

    /// <summary>
    /// The node for <paramref name="path"/> in a freshly scanned tree, or the deepest ancestor that
    /// survived. Used to put the user back where they were after a delete forced a rescan.
    /// </summary>
    private static DirNode DeepestExisting(DirNode root, string path)
    {
        if (Same(root.FullPath, path)) return root;

        DirNode current = root;

        while (true)
        {
            DirNode? next = null;

            foreach (DirNode child in current.Children)
            {
                if (child.IsDirectory && IsAncestorOrSelf(child.FullPath, path))
                {
                    next = child;
                    break;
                }
            }

            if (next is null) return current;
            if (Same(next.FullPath, path)) return next;

            current = next;
        }
    }

    private static bool IsAncestorOrSelf(string candidate, string path)
    {
        if (Same(candidate, path)) return true;

        // Compare against the candidate plus a separator, so "C:\Users" cannot swallow
        // "C:\UsersPublic".
        string prefix = candidate.TrimEnd('\\', '/') + System.IO.Path.DirectorySeparatorChar;
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool Same(string a, string b) =>
        string.Equals(a.TrimEnd('\\', '/'), b.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
}
