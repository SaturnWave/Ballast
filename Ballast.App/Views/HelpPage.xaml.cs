using Ballast.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// Help: what Ballast does, and&#8212;mostly&#8212;what it refuses to do.
///
/// <para>
/// The page is deliberately inert. It reads nothing from the disk, starts no scan, and its only
/// interactive control opens the audit log folder in Explorer. A page whose whole purpose is to be
/// trusted about deletion has no business doing anything.
/// </para>
/// </summary>
public sealed partial class HelpPage : Page
{
    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public HelpPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
    }

    /// <summary>The page's view model: the risk-level wording, the log folder and its button.</summary>
    public HelpViewModel ViewModel { get; } = new();
}
