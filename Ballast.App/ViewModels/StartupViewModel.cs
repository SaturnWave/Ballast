using System.Collections.ObjectModel;
using Ballast.Core.Startup;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>
/// One startup row.
/// </summary>
/// <remarks>
/// <see cref="IsEnabled"/> is <b>display state only</b>, and the switch binds to it one-way. The
/// actual change is driven by the page's <c>Toggled</c> handler calling
/// <see cref="StartupViewModel.ToggleAsync"/>.
///
/// <para>
/// It used to work the other way round: a two-way binding on <c>IsOn</c> plus a generated
/// <c>OnIsEnabledChanged</c> hook that performed the write as a side effect of the setter. That
/// silently did nothing — flipping a switch never reached the toggle service, so no startup item
/// could be turned off, and because the refusal path did not log, there was no trace of it either.
/// An explicit event is also simply the right shape for an operation that writes to the registry
/// and can legitimately fail; a property setter is the wrong place to hide that.
/// </para>
/// </remarks>
public sealed partial class StartupEntryViewModel : ObservableObject
{
    /// <summary>Wraps <paramref name="entry"/> for display.</summary>
    public StartupEntryViewModel(StartupEntry entry)
    {
        Entry = entry;
        IsEnabled = entry.IsEnabled;
    }

    /// <summary>The immutable Core record backing this row.</summary>
    public StartupEntry Entry { get; }

    /// <summary>Bound one-way to the iOS switch. Reflects the system, never drives it.</summary>
    [ObservableProperty]
    private bool _isEnabled;

    /// <summary>
    /// The program's own icon, filled in after the row is on screen. Null until then, and null
    /// forever for an entry whose executable could not be read.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasIcon))]
    [NotifyPropertyChangedFor(nameof(ShowGlyph))]
    private ImageSource? _icon;

    /// <summary>True once a real icon has been loaded for this row.</summary>
    public bool HasIcon => Icon is not null;

    /// <summary>
    /// True while there is no real icon, so the row falls back to its source glyph. One of this
    /// and <see cref="HasIcon"/> is always true, which is what keeps the column from going ragged
    /// as icons arrive one by one.
    /// </summary>
    public bool ShowGlyph => Icon is null;

    /// <summary>
    /// The executable an icon can be read from, or null when the command line did not resolve to
    /// a program. Doubles as the cache key, so it is the resolved path and not the raw command.
    /// </summary>
    public string? IconSourcePath => Entry.ExecutablePath;

    /// <summary>True when this row cannot be changed right now; the switch is greyed out.</summary>
    public bool CanChange => AppRoot.Services.StartupToggle.CanToggle(Entry, out _);

    /// <summary>Display name.</summary>
    public string Name => Entry.DisplayName;

    /// <summary>Publisher, then what it actually runs.</summary>
    public string SecondaryText => Entry.Publisher is { Length: > 0 } publisher
        ? $"{publisher}  -  {Entry.ExecutablePath ?? Entry.Command}"
        : Entry.ExecutablePath ?? Entry.Command;

    /// <summary>Where it lives, e.g. "For you" or "Scheduled task".</summary>
    public string SourceLabel => Entry.Source.DisplayName();

    /// <summary>Segoe Fluent Icons glyph for the source.</summary>
    public string Glyph => Entry.Source.Glyph();

    /// <summary>True when changing this entry needs an elevated process.</summary>
    public bool ShowAdminNote => Entry.RequiresAdmin;

    /// <summary>Badge copy for the admin note.</summary>
    public string AdminNote => "Needs administrator";

    /// <summary>Sets the displayed position. Purely visual; performs no system change.</summary>
    public void ShowAs(bool value) => IsEnabled = value;
}

/// <summary>
/// The startup manager.
/// </summary>
/// <remarks>
/// <para>
/// Loading is two-phase, matching what <see cref="StartupScanner"/> is built for: the registry keys
/// and Startup folders come back in milliseconds and paint immediately, then logon-triggered
/// scheduled tasks (a multi-second <c>schtasks.exe</c> round-trip) fold in when they arrive.
/// </para>
/// <para>
/// Program icons are a third, even lazier phase — see <see cref="QueueIconLoad"/>. They are
/// decoration, so they are never allowed in front of the rows they decorate.
/// </para>
/// <para>
/// Switching an entry off goes through <see cref="StartupToggleService"/>, which <em>moves</em> the
/// value or shortcut into a parallel store it owns rather than deleting it, so every change is
/// reversible. A refused change (machine-wide entry, no elevation) springs the switch back and says
/// why instead of silently doing nothing.
/// </para>
/// </remarks>
public sealed partial class StartupViewModel : ScanViewModelBase
{
    /// <summary>
    /// Pixel size asked of the shell. The row draws at 22px, so 32 covers a 125-150% display
    /// without paying for a jumbo icon that would only ever be scaled down.
    /// </summary>
    private const int IconPixelSize = 32;

    /// <summary>
    /// Decoded icons by executable path, including misses as null. Rows are thrown away and rebuilt
    /// on every scan and after every toggle, so without this the same icons would be re-read and
    /// re-decoded each time and the column would visibly flicker back to glyphs.
    /// </summary>
    /// <remarks>
    /// Only ever touched on the UI thread — a <see cref="BitmapImage"/> may not be created anywhere
    /// else — so a plain dictionary is correct here. The byte-level cache one layer down, in
    /// <see cref="FileIconExtractor"/>, is the thread-safe one.
    /// </remarks>
    private readonly Dictionary<string, ImageSource?> _icons = new(StringComparer.OrdinalIgnoreCase);

    private readonly DispatcherQueue? _uiQueue = DispatcherQueue.GetForCurrentThread();

    private IReadOnlyList<StartupEntry> _scheduledTasks = [];
    private CancellationTokenSource? _iconCts;

    /// <summary>Creates an empty list; the page runs <see cref="LoadCommand"/> when it appears.</summary>
    public StartupViewModel() => StatusText = "Reading startup entries...";

    /// <summary>Every startup entry, ordered by source then name.</summary>
    public ObservableCollection<StartupEntryViewModel> Entries { get; } = [];

    /// <summary>True once the fast phase of <see cref="LoadAsync"/> has completed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyState))]
    private bool _hasLoaded;

    /// <summary>True while the scheduled-task phase is still running.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ScheduledTaskNote))]
    private bool _isLoadingScheduledTasks;

    /// <summary>Set while a toggle is being applied, so the list does not accept a second flip.</summary>
    [ObservableProperty]
    private bool _isApplying;

    /// <summary>True when nothing launches with Windows.</summary>
    public bool ShowEmptyState => HasLoaded && Entries.Count == 0;

    /// <summary>Note shown while the slow scheduled-task phase is still running.</summary>
    public string ScheduledTaskNote => IsLoadingScheduledTasks
        ? "Also checking logon-triggered scheduled tasks..."
        : string.Empty;

    /// <summary>Footnote for the whole page.</summary>
    public string PageFootnote =>
        "Switching an entry off moves it into a store Ballast owns, so it can always be put " +
        "back. Machine-wide entries need Ballast restarted as administrator.";

    /// <summary>
    /// Reads the registry keys and Startup folders, paints them, then folds in scheduled tasks.
    /// </summary>
    [RelayCommand]
    private async Task LoadAsync()
    {
        if (IsBusy) return;

        CancellationToken ct = BeginOperation("Reading startup entries...");

        try
        {
            _scheduledTasks = [];

            IReadOnlyList<StartupEntry> local = await AppRoot.Services.Startup.ScanFastAsync(ct);
            Rebuild(local);
            StatusText = Summarise();
        }
        catch (OperationCanceledException)
        {
            StatusText = "Cancelled.";
            return;
        }
        catch (Exception ex)
        {
            AppLog.Write("Startup enumeration failed.", ex);
            StatusText = $"Could not read startup entries: {ex.Message}";
            return;
        }
        finally
        {
            HasLoaded = true;
            EndOperation();
            OnPropertyChanged(nameof(ShowEmptyState));
        }

        await MergeScheduledTasksAsync(ct);
    }

    /// <summary>
    /// The slow half of a scan. Awaited by <see cref="LoadAsync"/> after the fast rows are already
    /// on screen, so the page never shows a spinner for eight seconds to gain a couple of rows.
    /// </summary>
    private async Task MergeScheduledTasksAsync(CancellationToken ct)
    {
        IsLoadingScheduledTasks = true;

        try
        {
            _scheduledTasks = await AppRoot.Services.Startup.ScanScheduledTasksAsync(ct);
            if (_scheduledTasks.Count == 0) return;

            // Snapshot the existing rows before Rebuild clears the collection.
            List<StartupEntry> combined = [.. Entries.Select(e => e.Entry), .. _scheduledTasks];
            Rebuild(combined);
            StatusText = Summarise();
        }
        catch (OperationCanceledException)
        {
            // A newer load superseded this one; nothing to report.
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not read logon-triggered scheduled tasks.", ex);
        }
        finally
        {
            IsLoadingScheduledTasks = false;
            OnPropertyChanged(nameof(ShowEmptyState));
        }
    }

    private void Rebuild(IEnumerable<StartupEntry> entries)
    {
        Entries.Clear();

        foreach (StartupEntry entry in StartupScanner.Deduplicate(entries))
        {
            StartupEntryViewModel row = new(entry);

            // Icons already known from an earlier pass are attached before the row is added, so a
            // rescan or a toggle repaints with its icons intact instead of flashing back to glyphs.
            if (row.IconSourcePath is { Length: > 0 } path &&
                _icons.TryGetValue(path, out ImageSource? known))
            {
                row.Icon = known;
            }

            Entries.Add(row);
        }

        QueueIconLoad();
    }

    /// <summary>
    /// Schedules the icon pass to start once the rows are actually on screen.
    /// </summary>
    /// <remarks>
    /// The point of this page is that the registry and Startup folders come back in tens of
    /// milliseconds and paint immediately. Reading a dozen icons out of a dozen binaries costs more
    /// than the entire scan did, so it happens at
    /// <see cref="DispatcherQueuePriority.Low"/> — behind the layout pass that puts the rows on
    /// screen — and never on the path that produces them. Each queued pass supersedes the last, so
    /// a burst of rescans does not leave several loops fighting over the same rows.
    /// </remarks>
    private void QueueIconLoad()
    {
        _iconCts?.Cancel();
        _iconCts?.Dispose();
        _iconCts = new CancellationTokenSource();

        // No dispatcher means this view model was built off the UI thread, and there is then no
        // thread a BitmapImage may be created on. Every row keeps its glyph, which is a complete
        // and correct rendering of the page rather than a degraded one.
        if (_uiQueue is null) return;

        CancellationToken ct = _iconCts.Token;

        _uiQueue.TryEnqueue(DispatcherQueuePriority.Low, () => _ = LoadIconsAsync(ct));
    }

    /// <summary>
    /// Fills in each row's icon, one row at a time.
    /// </summary>
    /// <remarks>
    /// Deliberately sequential rather than a <c>WhenAll</c>: the rows fill in visibly from the top,
    /// each await hands the UI thread back, and a long list cannot dump dozens of shell calls onto
    /// the thread pool at once. A row that yields nothing keeps the glyph it was born with.
    /// </remarks>
    private async Task LoadIconsAsync(CancellationToken ct)
    {
        try
        {
            foreach (StartupEntryViewModel row in Entries.ToList())
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
            // Neither call in the loop throws on cancellation, so this really is only for surprises.
            AppLog.Write("Could not load startup program icons.", ex);
        }
    }

    /// <summary>
    /// Turns PNG bytes into something XAML can draw. Must run on the UI thread, because that is the
    /// only thread a <see cref="BitmapImage"/> may be created on.
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
            AppLog.Write("Could not decode a startup program icon.", ex);
            return null;
        }
    }

    private string Summarise()
    {
        if (Entries.Count == 0) return "Nothing launches with Windows.";

        int enabled = Entries.Count(e => e.IsEnabled);
        return $"{enabled:N0} of {Entries.Count:N0} entries are enabled.";
    }

    /// <summary>
    /// Applies one switch flip. Checks first, acts second, and always leaves the switch showing the
    /// state the system is actually in.
    /// </summary>
    /// <remarks>
    /// Called by <c>StartupPage</c>'s <c>Toggled</c> handler — not by a property setter. Every exit
    /// path either performs the change or writes a reason into <see cref="ScanViewModelBase.StatusText"/>
    /// and puts the switch back, so the UI can never disagree with the system.
    /// </remarks>
    public async Task ToggleAsync(StartupEntryViewModel row, bool desired)
    {
        ArgumentNullException.ThrowIfNull(row);

        if (row.IsEnabled == desired) return; // already there; nothing to do

        if (IsApplying)
        {
            row.ShowAs(!desired);
            return;
        }

        StartupToggleService toggle = AppRoot.Services.StartupToggle;

        if (!toggle.CanToggle(row.Entry, out string? reason))
        {
            row.ShowAs(!desired);
            reason ??= "That startup item cannot be changed.";
            StatusText = reason;

            // The refusal path used to be the one path that left no trace, which is why this bug
            // was invisible in the log.
            AppLog.Write($"Refused to toggle startup entry '{row.Entry.Name}': {reason}");
            return;
        }

        IsApplying = true;

        try
        {
            await toggle.SetEnabledAsync(row.Entry, desired);

            StatusText = desired
                ? $"{row.Name} will launch when you sign in."
                : $"{row.Name} will not launch when you sign in. Ballast kept a copy so this is reversible.";

            // Entries are immutable, so Location is stale after a successful move: rescan the
            // cheap stores and reuse the scheduled tasks we already have.
            await ReloadLocalStoresAsync(row.Entry.Source);
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not toggle startup entry '{row.Entry.Name}'.", ex);
            row.ShowAs(!desired);
            StatusText = ex.Message;
        }
        finally
        {
            IsApplying = false;
        }
    }

    private async Task ReloadLocalStoresAsync(StartupSource toggledSource)
    {
        try
        {
            IReadOnlyList<StartupEntry> local = await AppRoot.Services.Startup.ScanFastAsync();

            // A task we just changed makes the cached task list stale, so re-query it rather than
            // showing an entry whose switch disagrees with the system.
            if (toggledSource is StartupSource.ScheduledTask)
            {
                _scheduledTasks = [];
                Rebuild(local);
                StatusText = Summarise();
                await MergeScheduledTasksAsync(CancellationToken.None);
                return;
            }

            List<StartupEntry> combined = [.. local, .. _scheduledTasks];
            Rebuild(combined);
            StatusText = Summarise();
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not refresh startup entries after a toggle.", ex);
        }
    }
}
