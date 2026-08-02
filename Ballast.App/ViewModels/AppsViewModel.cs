using System.Collections.ObjectModel;
using Ballast.Core.Programs;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;

namespace Ballast.App.ViewModels;

/// <summary>How the installed-programs list is ordered.</summary>
public enum ProgramSort
{
    /// <summary>Alphabetical. The default, and the only order every row can be placed in.</summary>
    Name,

    /// <summary>Largest first. Programs with no recorded size sink to the bottom.</summary>
    Size,

    /// <summary>Most recently installed first. Programs with no recorded date sink to the bottom.</summary>
    InstallDate,
}

/// <summary>One segment of the sort control.</summary>
public sealed partial class ProgramSortOptionViewModel : ObservableObject
{
    private readonly Action<ProgramSortOptionViewModel> _onSelected;
    private readonly Func<ProgramSort, bool> _isActive;

    /// <summary>Creates a segment.</summary>
    /// <param name="value">The order this segment selects.</param>
    /// <param name="label">Segment caption.</param>
    /// <param name="onSelected">Called when the user picks this segment.</param>
    /// <param name="isActive">Asks the owner which order is currently in force.</param>
    public ProgramSortOptionViewModel(
        ProgramSort value,
        string label,
        Action<ProgramSortOptionViewModel> onSelected,
        Func<ProgramSort, bool> isActive)
    {
        Value = value;
        Label = label;
        _onSelected = onSelected;
        _isActive = isActive;
    }

    /// <summary>The order this segment selects.</summary>
    public ProgramSort Value { get; }

    /// <summary>Segment caption.</summary>
    public string Label { get; }

    /// <summary>Bound two-way to the segment's ToggleButton.</summary>
    [ObservableProperty]
    private bool _isSelected;

    partial void OnIsSelectedChanged(bool value)
    {
        if (value)
        {
            _onSelected(this);
            return;
        }

        // Clicking the segment that is already selected un-checks the ToggleButton, which would
        // leave the control showing no answer at all while the list stayed sorted that way. A
        // segmented control always has exactly one answer, so put it straight back.
        if (_isActive(Value)) IsSelected = true;
    }
}

/// <summary>
/// One row of the installed-programs list.
/// </summary>
/// <remarks>
/// Display only. Nothing on this type removes anything: the row's Uninstall button goes through
/// <c>AppsPage</c>'s confirmation dialog and then <see cref="AppsViewModel.UninstallAsync"/>, which
/// starts the vendor's own uninstaller and nothing else.
/// </remarks>
public sealed partial class InstalledProgramViewModel : ObservableObject
{
    /// <summary>Wraps <paramref name="program"/> for display.</summary>
    public InstalledProgramViewModel(InstalledProgram program)
    {
        Program = program;
        IconSourcePath = ResolveIconPath(program);
    }

    /// <summary>The immutable Core record backing this row.</summary>
    public InstalledProgram Program { get; }

    /// <summary>
    /// The file an icon can be read from, or null when the registry did not point at one. Doubles
    /// as the icon cache key, so it is the resolved path rather than the raw <c>DisplayIcon</c>.
    /// </summary>
    public string? IconSourcePath { get; }

    /// <summary>
    /// The program's own icon, filled in after the row is on screen. Null until then, and null
    /// forever for a program whose icon could not be read.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasIcon))]
    [NotifyPropertyChangedFor(nameof(ShowGlyph))]
    private ImageSource? _icon;

    /// <summary>
    /// True once the user has opened this program's uninstaller in this session. The row says so
    /// rather than disappearing, because the uninstall finishes in another process and this list
    /// has no way to know how it went.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowLaunchedNote))]
    private bool _uninstallerOpened;

    /// <summary>True once a real icon has been loaded for this row.</summary>
    public bool HasIcon => Icon is not null;

    /// <summary>
    /// True while there is no real icon, so the row falls back to a neutral glyph. One of this and
    /// <see cref="HasIcon"/> is always true, which keeps the column from going ragged as icons
    /// arrive one by one.
    /// </summary>
    public bool ShowGlyph => Icon is null;

    /// <summary>Program name.</summary>
    public string Name => Program.DisplayName;

    /// <summary>Publisher and version, as far as the registry recorded them.</summary>
    public string SecondaryText
    {
        get
        {
            string publisher = Program.Publisher ?? "Publisher not recorded";

            return Program.Version is { Length: > 0 } version
                ? $"{publisher}  -  version {version}"
                : publisher;
        }
    }

    /// <summary>Install date and scope, as a caption.</summary>
    public string CaptionText
    {
        get
        {
            string scope = Program.Scope.DisplayName();

            return Program.InstallDate is { } date
                ? $"Installed {date:d}  -  {scope}"
                : $"Install date not recorded  -  {scope}";
        }
    }

    /// <summary>Size on disk, or an em dash when the registry did not record one.</summary>
    public string SizeText => Program.SizeDisplay;

    /// <summary>Fallback glyph, shown until (or instead of) the program's real icon.</summary>
    public string Glyph => "\uE7C3";

    /// <summary>True when Windows will ask for administrator permission.</summary>
    public bool ShowAdminNote => Program.RequiresAdmin;

    /// <summary>Badge copy for the administrator note.</summary>
    public string AdminNote => "Needs administrator";

    /// <summary>True when there is an uninstaller to start.</summary>
    public bool CanUninstall => Program.CanUninstall;

    /// <summary>True when the row should explain why there is no button.</summary>
    public bool ShowNoUninstallerNote => !Program.CanUninstall;

    /// <summary>Copy for that explanation.</summary>
    public string NoUninstallerNote => "No uninstaller registered";

    /// <summary>True once the uninstaller has been opened for this row.</summary>
    public bool ShowLaunchedNote => UninstallerOpened;

    /// <summary>Badge copy after a launch.</summary>
    public string LaunchedNote => "Uninstaller opened";

    /// <summary>True when the registry supplied a silent command line of its own.</summary>
    public bool HasQuietUninstall => Program.HasQuietUninstall;

    /// <summary>Where the program says it is installed, for the confirmation dialog.</summary>
    public string LocationText => Program.InstallLocation is { Length: > 0 } location
        ? location
        : "Install folder not recorded";

    /// <summary>True when the search box's query matches this row's name or publisher.</summary>
    public bool Matches(string query) =>
        Name.Contains(query, StringComparison.CurrentCultureIgnoreCase)
        || (Program.Publisher?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false);

    /// <summary>
    /// Turns a raw <c>DisplayIcon</c> value into a path an icon can be read from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>DisplayIcon</c> is usually a plain path, but the <c>"C:\App\app.exe,0"</c> form — a file
    /// plus a resource index — is common too. The index is stripped only when everything after the
    /// last comma is digits, because a path may legitimately contain one
    /// (<c>C:\Acme, Inc\app.exe</c>).
    /// </para>
    /// <para>
    /// Deliberately no fallback to <c>UninstallString</c>: that would decorate the row with the
    /// uninstaller's icon, which is generic on most installers and actively misleading on the rest.
    /// A row with nothing to show keeps its glyph.
    /// </para>
    /// </remarks>
    private static string? ResolveIconPath(InstalledProgram program)
    {
        if (program.IconPath is not { Length: > 0 } raw) return null;

        string path = raw.Trim().Trim('"').Trim();
        if (path.Length == 0) return null;

        int comma = path.LastIndexOf(',');

        if (comma > 0)
        {
            string suffix = path[(comma + 1)..].Trim();
            if (suffix.StartsWith('-')) suffix = suffix[1..];

            if (suffix.Length > 0 && suffix.All(char.IsAsciiDigit))
                path = path[..comma].Trim().Trim('"').Trim();
        }

        return path.Length == 0 ? null : path;
    }
}

/// <summary>
/// The installed-programs page: the list Add or Remove Programs shows, with a search box, a sort
/// control, and a per-row button that starts the program's own uninstaller.
/// </summary>
/// <remarks>
/// <para>
/// <b>Ballast never removes a program itself.</b> The only action this view model can take is
/// asking <see cref="UninstallLauncher"/> to start the vendor's uninstaller. It does not delete
/// install folders, it does not delete registry keys, and it does not "clean up leftovers" —
/// deleting an install directory behind an uninstaller's back is how a machine ends up with
/// half-removed software, broken shared components and registry entries pointing at nothing.
/// </para>
/// <para>
/// Because the uninstaller runs as its own process, the outcome is unknowable from here.
/// <see cref="UninstallAsync"/> therefore reports only that the uninstaller was <em>opened</em> and
/// asks the user to rescan, rather than crossing the program off the list as though it were gone.
/// </para>
/// </remarks>
public sealed partial class AppsViewModel : ScanViewModelBase
{
    private const int IconPixelSize = 32;

    private readonly InstalledProgramScanner _scanner = new();
    private readonly UninstallLauncher _launcher = new();

    /// <summary>
    /// Decoded icons by source path, misses included as null, so a rescan or a change of sort does
    /// not re-read the same binaries or flicker the column back to glyphs.
    /// </summary>
    /// <remarks>
    /// Only ever touched on the UI thread — a <see cref="BitmapImage"/> may not be created anywhere
    /// else — so a plain dictionary is right here. The byte-level cache one layer down, in
    /// <see cref="FileIconExtractor"/>, is the thread-safe one.
    /// </remarks>
    private readonly Dictionary<string, ImageSource?> _icons = new(StringComparer.OrdinalIgnoreCase);

    private readonly DispatcherQueue? _uiQueue = DispatcherQueue.GetForCurrentThread();

    private List<InstalledProgramViewModel> _all = [];
    private CancellationTokenSource? _iconCts;

    /// <summary>Creates an empty list; the page runs <see cref="LoadCommand"/> when it appears.</summary>
    public AppsViewModel()
    {
        StatusText = "Reading installed programs...";
        SearchText = string.Empty;
        LeftoverNote = string.Empty;
        PendingNote = string.Empty;

        SortOptions.Add(new ProgramSortOptionViewModel(ProgramSort.Name, "Name", OnSortSelected, IsActiveSort));
        SortOptions.Add(new ProgramSortOptionViewModel(ProgramSort.Size, "Size", OnSortSelected, IsActiveSort));
        SortOptions.Add(new ProgramSortOptionViewModel(
            ProgramSort.InstallDate, "Installed", OnSortSelected, IsActiveSort));

        SyncSortOptions();
    }

    /// <summary>The rows on screen: filtered by <see cref="SearchText"/>, then ordered by <see cref="Sort"/>.</summary>
    public ObservableCollection<InstalledProgramViewModel> Programs { get; } = [];

    /// <summary>The three sort segments.</summary>
    public ObservableCollection<ProgramSortOptionViewModel> SortOptions { get; } = [];

    /// <summary>Filters by name and publisher. Empty shows everything.</summary>
    [ObservableProperty]
    private string _searchText;

    /// <summary>The active order.</summary>
    [ObservableProperty]
    private ProgramSort _sort;

    /// <summary>True once a scan has finished, successfully or not.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    [NotifyPropertyChangedFor(nameof(ShowNoMatches))]
    private bool _hasLoaded;

    /// <summary>Set while an uninstaller is being started, so a second click cannot land.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanAct))]
    private bool _isLaunching;

    /// <summary>Reminder to rescan once an uninstaller has been opened.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowPendingNote))]
    private string _pendingNote;

    /// <summary>
    /// Note about a folder still on disk after a program stopped being listed. Purely
    /// informational: nothing here removes it, and the wording says so.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowLeftoverNote))]
    private string _leftoverNote;

    /// <summary>True when there is a rescan reminder to show.</summary>
    public bool ShowPendingNote => !string.IsNullOrWhiteSpace(PendingNote);

    /// <summary>True when there is a leftover-folder note to show.</summary>
    public bool ShowLeftoverNote => !string.IsNullOrWhiteSpace(LeftoverNote);

    /// <summary>True when nothing at all could be read.</summary>
    public bool ShowEmptyState => HasLoaded && _all.Count == 0;

    /// <summary>True when the list has rows but the search matched none of them.</summary>
    public bool ShowNoMatches => HasLoaded && _all.Count > 0 && Programs.Count == 0;

    /// <summary>True when the page will accept a click on an Uninstall button.</summary>
    public bool CanAct => !IsLaunching;

    /// <summary>Header count, e.g. "148 programs".</summary>
    public string CountText => _all.Count switch
    {
        0 => "No programs",
        1 => "1 program",
        _ => $"{_all.Count:N0} programs",
    };

    /// <summary>The page's standing promise, shown as the list's footnote.</summary>
    public string PageFootnote =>
        "Uninstalling opens the program's own uninstaller, which is the only thing that knows how " +
        "to undo the installation properly - which shared components are still needed, which " +
        "services to stop, and what saved data is about to go. Ballast does not delete a program's " +
        "files or registry keys, before or after. Anything left behind is reported, never removed.";

    /// <summary>Reads all three uninstall registries and rebuilds the list.</summary>
    [RelayCommand]
    private async Task LoadAsync()
    {
        if (IsBusy) return;

        CancellationToken ct = BeginOperation("Reading installed programs...");

        // Snapshot what an uninstaller was opened for, so the leftover check below has something
        // to look for and the rows can keep saying so after the rescan.
        List<InstalledProgramViewModel> launched = [.. _all.Where(p => p.UninstallerOpened)];

        try
        {
            IReadOnlyList<InstalledProgram> programs = await _scanner.ScanAsync(ct);

            _all = [.. programs.Select(CreateRow)];
            RestoreLaunchedFlags(launched);
            ApplyView();

            StatusText = Summarise();
            ReportLeftovers(launched);
            QueueIconLoad();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Cancelled.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Reading the installed-programs registry failed.", ex);
            StatusText = $"Could not read the list of installed programs: {ex.Message}";
        }
        finally
        {
            HasLoaded = true;
            EndOperation();
            OnPropertyChanged(nameof(CountText));
            OnPropertyChanged(nameof(ShowEmptyState));
            OnPropertyChanged(nameof(ShowNoMatches));
        }
    }

    /// <summary>
    /// Starts <paramref name="row"/>'s own uninstaller. Called by the page <em>after</em> the user
    /// has confirmed a dialog spelling out what is about to happen.
    /// </summary>
    /// <param name="row">The row whose uninstaller should be opened.</param>
    /// <param name="preferQuiet">
    /// Use the registry's own <c>QuietUninstallString</c>. Ignored unless the registry provides
    /// one: no silent flag is ever invented.
    /// </param>
    /// <returns>True when the uninstaller process started — not that the uninstall succeeded.</returns>
    public async Task<bool> UninstallAsync(InstalledProgramViewModel row, bool preferQuiet = false)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (IsLaunching) return false;

        if (!row.CanUninstall)
        {
            StatusText =
                $"{row.Name} did not register an uninstaller, so there is nothing for Ballast to " +
                "start. Ballast will not try to remove it by hand.";
            return false;
        }

        IsLaunching = true;
        LeftoverNote = string.Empty;

        try
        {
            bool started = await _launcher.LaunchAsync(row.Program, preferQuiet);

            if (started)
            {
                row.UninstallerOpened = true;
                PendingNote = $"{row.Name}: {UninstallLauncher.RescanHint}";
                StatusText = $"Opened {row.Name}'s uninstaller. Ballast has removed nothing itself.";
                return true;
            }

            // The launcher has already written the detail to the action log; keep the UI honest
            // about the fact that nothing happened.
            StatusText =
                $"{row.Name}'s uninstaller did not start, so nothing has changed. It may have been " +
                "cancelled at the administrator prompt.";
            return false;
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not start the uninstaller for '{row.Name}'.", ex);
            StatusText = $"Could not start {row.Name}'s uninstaller: {ex.Message}";
            return false;
        }
        finally
        {
            IsLaunching = false;
        }
    }

    partial void OnSearchTextChanged(string value) => ApplyView();

    partial void OnSortChanged(ProgramSort value)
    {
        SyncSortOptions();
        ApplyView();
    }

    private void OnSortSelected(ProgramSortOptionViewModel option) => Sort = option.Value;

    private bool IsActiveSort(ProgramSort candidate) => candidate == Sort;

    private void SyncSortOptions()
    {
        foreach (ProgramSortOptionViewModel option in SortOptions)
            option.IsSelected = option.Value == Sort;
    }

    /// <summary>Builds a row, attaching any icon already known from an earlier pass.</summary>
    private InstalledProgramViewModel CreateRow(InstalledProgram program)
    {
        InstalledProgramViewModel row = new(program);

        if (row.IconSourcePath is { Length: > 0 } path && _icons.TryGetValue(path, out ImageSource? known))
            row.Icon = known;

        return row;
    }

    /// <summary>Rebuilds <see cref="Programs"/> from the full list, applying the filter and order.</summary>
    /// <remarks>
    /// The row objects are reused rather than rebuilt, so filtering and re-sorting never discard an
    /// icon that has already been decoded — and typing in the search box costs no shell calls.
    /// </remarks>
    private void ApplyView()
    {
        string query = SearchText?.Trim() ?? string.Empty;

        IEnumerable<InstalledProgramViewModel> matching = query.Length == 0
            ? _all
            : _all.Where(p => p.Matches(query));

        Programs.Clear();

        foreach (InstalledProgramViewModel row in Order(matching))
            Programs.Add(row);

        OnPropertyChanged(nameof(ShowNoMatches));
    }

    /// <summary>
    /// Applies the chosen order. Both the size and date orders put "not recorded" last: those
    /// values are missing far too often for an unknown to be allowed to masquerade as a zero-byte
    /// program or an ancient install.
    /// </summary>
    private IEnumerable<InstalledProgramViewModel> Order(IEnumerable<InstalledProgramViewModel> rows) => Sort switch
    {
        ProgramSort.Size => rows
            .OrderByDescending(p => p.Program.EstimatedSizeBytes is not null)
            .ThenByDescending(p => p.Program.EstimatedSizeBytes ?? 0L)
            .ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase),

        ProgramSort.InstallDate => rows
            .OrderByDescending(p => p.Program.InstallDate is not null)
            .ThenByDescending(p => p.Program.InstallDate ?? DateOnly.MinValue)
            .ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase),

        _ => rows.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase),
    };

    /// <summary>
    /// Carries the "uninstaller opened" mark across a rescan, so a program whose uninstaller the
    /// user cancelled does not quietly look untouched.
    /// </summary>
    private void RestoreLaunchedFlags(IEnumerable<InstalledProgramViewModel> launched)
    {
        HashSet<string> keys = new(
            launched.Select(p => p.Program.RegistryKeyPath),
            StringComparer.OrdinalIgnoreCase);

        if (keys.Count == 0) return;

        foreach (InstalledProgramViewModel row in _all)
        {
            if (keys.Contains(row.Program.RegistryKeyPath)) row.UninstallerOpened = true;
        }
    }

    /// <summary>
    /// After a rescan, notes any install folder still on disk for a program that has stopped being
    /// listed. Reported only. Ballast does not delete it, and the note says so plainly, because
    /// what looks like a leftover is very often the user's own documents, a licence file, or a
    /// shared component another program is still using.
    /// </summary>
    private void ReportLeftovers(IEnumerable<InstalledProgramViewModel> launched)
    {
        try
        {
            HashSet<string> stillListed = new(
                _all.Select(p => p.Program.RegistryKeyPath),
                StringComparer.OrdinalIgnoreCase);

            InstalledProgram[] gone =
            [
                .. launched
                    .Where(p => !stillListed.Contains(p.Program.RegistryKeyPath))
                    .Select(p => p.Program)
            ];

            if (gone.Length == 0)
            {
                LeftoverNote = string.Empty;
                return;
            }

            IReadOnlyList<string> remaining = UninstallLauncher.FindRemainingFolders(gone);

            LeftoverNote = remaining.Count == 0
                ? string.Empty
                : "Still on disk after uninstalling: "
                    + string.Join("  |  ", remaining)
                    + ".  Ballast will not remove these. A folder left behind often holds your own "
                    + "documents, licences or saved data, and a shared component another program "
                    + "still needs looks exactly the same from out here.";
        }
        catch (Exception ex)
        {
            // A leftover note is a nicety; failing to produce one must not disturb the scan.
            AppLog.Write("Could not check for leftover install folders.", ex);
            LeftoverNote = string.Empty;
        }
    }

    /// <summary>
    /// Schedules the icon pass to start once the rows are actually on screen.
    /// </summary>
    /// <remarks>
    /// Reading icons out of a few hundred binaries costs far more than the registry scan did, so it
    /// runs at <see cref="DispatcherQueuePriority.Low"/> — behind the layout pass that puts the
    /// rows on screen — and never on the path that produces them. Each queued pass supersedes the
    /// last, so a burst of rescans cannot leave several loops fighting over the same rows.
    /// </remarks>
    private void QueueIconLoad()
    {
        _iconCts?.Cancel();
        _iconCts?.Dispose();
        _iconCts = new CancellationTokenSource();

        // No dispatcher means this view model was built off the UI thread, and there is then no
        // thread a BitmapImage may be created on. Every row keeps its glyph, which is a complete
        // rendering of the page rather than a degraded one.
        if (_uiQueue is null) return;

        CancellationToken ct = _iconCts.Token;

        _uiQueue.TryEnqueue(DispatcherQueuePriority.Low, () => _ = LoadIconsAsync(ct));
    }

    /// <summary>
    /// Fills in each row's icon, one row at a time.
    /// </summary>
    /// <remarks>
    /// Deliberately sequential rather than a <c>WhenAll</c>: the rows fill in visibly, each await
    /// hands the UI thread back, and a long list cannot dump hundreds of shell calls onto the
    /// thread pool at once. A row that yields nothing keeps the glyph it was born with.
    /// </remarks>
    private async Task LoadIconsAsync(CancellationToken ct)
    {
        try
        {
            foreach (InstalledProgramViewModel row in _all.ToList())
            {
                if (ct.IsCancellationRequested) return;
                if (row.Icon is not null) continue;
                if (row.IconSourcePath is not { Length: > 0 } path) continue;

                if (_icons.TryGetValue(path, out ImageSource? known))
                {
                    row.Icon = known;
                    continue;
                }

                byte[]? png = await FileIconExtractor.TryGetPngAsync(path, IconPixelSize, ct);
                if (ct.IsCancellationRequested) return;

                ImageSource? icon = png is null ? null : await DecodeAsync(png);
                if (ct.IsCancellationRequested) return;

                // Misses are remembered too, so a program with no readable icon is asked once.
                _icons[path] = icon;
                row.Icon = icon;
            }
        }
        catch (Exception ex)
        {
            // An icon is decoration. Losing one must not disturb a page that is otherwise correct.
            AppLog.Write("Could not load installed-program icons.", ex);
        }
    }

    /// <summary>
    /// Decodes PNG bytes into something XAML can draw. Must run on the UI thread: that is the only
    /// thread a <see cref="BitmapImage"/> may be created on.
    /// </summary>
    private static async Task<ImageSource?> DecodeAsync(byte[] png)
    {
        try
        {
            using InMemoryRandomAccessStream stream = new();

            // DataWriter rather than the AsStream/AsBuffer extension methods: this is plain WinRT
            // and needs no interop shim to be present.
            using (DataWriter writer = new(stream))
            {
                writer.WriteBytes(png);
                await writer.StoreAsync();
                await writer.FlushAsync();

                // Detach first, or disposing the writer closes the stream we are about to read.
                writer.DetachStream();
            }

            stream.Seek(0);

            BitmapImage image = new();
            await image.SetSourceAsync(stream);

            return image;
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not decode an installed-program icon.", ex);
            return null;
        }
    }

    private string Summarise() => _all.Count == 0
        ? "No installed programs were found in the uninstall registry."
        : $"{_all.Count:N0} programs are installed.";
}
