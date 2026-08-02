using Ballast.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// The Security page: what Windows reports about the antivirus protecting this PC, followed by a
/// set of structural checks Ballast ran itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>Ballast is not an antivirus and this page never claims otherwise.</b> It has no signature
/// database and does not try to identify known malware — that is Windows Defender's job, which is
/// why Defender's own state is the first thing on the page rather than a footnote under Ballast's
/// results. What is left for Ballast to add is behavioural and structural: a program that added
/// itself to startup and is unsigned, something running from a place programs do not usually run
/// from. Those are worth a human's attention, and they are all this page ever claims.
/// </para>
/// <para>
/// The code-behind is deliberately thin. There is no confirmation dialog here because there is
/// nothing destructive to confirm: the page reveals files, hands paths to Defender, and switches
/// startup entries off through <c>StartupToggleService</c>, which moves them into a store Ballast
/// owns rather than deleting them. Nothing on this page can lose data, so a dialog would be
/// ceremony — and ceremony around harmless actions is how users learn to click through the dialogs
/// that do matter.
/// </para>
/// </remarks>
public sealed partial class SecurityPage : Page
{
    private bool _loaded;

    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public SecurityPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
        Loaded += OnLoaded;
    }

    /// <summary>The page's view model.</summary>
    public SecurityViewModel ViewModel { get; } = new();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Every check is read-only — the registry, the uninstall keys, Authenticode signatures and
        // whatever Windows will say about Defender — so running them on first show costs the user
        // nothing and is what the other pages do. The run reports progress and the Stop button is
        // live throughout.
        if (_loaded) return;
        _loaded = true;

        try
        {
            await ViewModel.RunChecksCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            // RunChecksAsync handles its own failures and writes the reason into the page. This
            // catches only the unexpected, because an exception escaping an async void handler
            // takes the whole app down.
            AppLog.Write("The Security page failed to run its checks.", ex);
        }
    }
}
