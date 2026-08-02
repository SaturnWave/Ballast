using Ballast.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// Settings: appearance, a shortcut to the log folder, and an About section that also publishes the
/// deletion allowlist so the user can audit exactly what the app is willing to touch.
/// </summary>
public sealed partial class SettingsPage : Page
{
    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public SettingsPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
    }

    /// <summary>The page's view model.</summary>
    public SettingsViewModel ViewModel { get; } = new();
}
