using Ballast.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// The startup manager: a grouped list of everything Windows launches at sign-in, each with its own
/// program icon and a switch. Both reading and writing are wired up — see
/// <see cref="OnEntryToggled"/>. Icons are filled in by the view model after this page has painted,
/// so nothing here waits on them.
/// </summary>
public sealed partial class StartupPage : Page
{
    private bool _loaded;

    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public StartupPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
        Loaded += OnLoaded;
    }

    /// <summary>The page's view model.</summary>
    public StartupViewModel ViewModel { get; } = new();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Enumerating the registry is read-only and cheap, so it is safe to do on first show.
        if (_loaded) return;
        _loaded = true;

        try
        {
            await ViewModel.LoadCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            AppLog.Write("Startup page failed to load its entries.", ex);
        }
    }

    /// <summary>
    /// Turns a switch flip into a real change.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>Toggled</c> also fires when the switch position is set programmatically — including while
    /// the list is rebuilt after a scan, which would otherwise re-apply a change the user never
    /// made. Comparing against the row's own display state makes those echoes no-ops:
    /// <c>ToggleAsync</c> returns immediately when the row already shows the requested position.
    /// </para>
    /// </remarks>
    private async void OnEntryToggled(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleSwitch { DataContext: StartupEntryViewModel row } toggle) return;

        try
        {
            await ViewModel.ToggleAsync(row, toggle.IsOn);
        }
        catch (Exception ex)
        {
            // ToggleAsync handles its own failures; this only catches anything truly unexpected,
            // because an exception escaping an async void handler would take the app down.
            AppLog.Write($"Unexpected failure toggling '{row.Entry.Name}'.", ex);
        }
    }
}
