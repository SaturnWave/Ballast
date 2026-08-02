using Ballast.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// The landing page: a hero card with the reclaimable total and Smart Scan, plus three summary
/// rows that drill into the matching page.
/// </summary>
public sealed partial class DashboardPage : Page
{
    private bool _factsLoaded;

    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public DashboardPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
        Loaded += OnLoaded;
    }

    /// <summary>The page's view model.</summary>
    public DashboardViewModel ViewModel { get; } = new();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Drive capacity and the fast half of the startup inventory are both read-only and cheap,
        // so they can populate on first show. Junk still waits for an explicit Smart Scan.
        if (_factsLoaded) return;
        _factsLoaded = true;

        try
        {
            await ViewModel.RefreshCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            AppLog.Write("Dashboard could not load its summary facts.", ex);
        }
    }

    private void OnJunkRowClick(object sender, RoutedEventArgs e) =>
        MainWindow.Instance?.NavigateTo("cleanup");

    private void OnDriveRowClick(object sender, RoutedEventArgs e) =>
        MainWindow.Instance?.NavigateTo("diskspace");

    private void OnStartupRowClick(object sender, RoutedEventArgs e) =>
        MainWindow.Instance?.NavigateTo("startup");
}
