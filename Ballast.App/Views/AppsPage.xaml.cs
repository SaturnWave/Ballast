using Ballast.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// The installed-programs list — Windows' own "Apps &amp; features", with sizes and icons.
/// </summary>
/// <remarks>
/// <para>
/// Uninstalling here means <b>starting the program's own uninstaller</b>. Ballast never deletes a
/// program's files or registry keys itself, and the confirmation below says so in as many words.
/// Removing an install folder by hand is how a machine ends up with half-removed software, broken
/// shared components and a registry pointing at nothing — it is the mistake this whole page is
/// shaped to avoid.
/// </para>
/// <para>
/// Because the uninstaller runs outside this process, the page never claims a program is gone. It
/// says the uninstaller was opened and asks the user to rescan once it finishes.
/// </para>
/// </remarks>
public sealed partial class AppsPage : Page
{
    /// <summary>Guards the confirm-then-launch sequence against a second click landing mid-dialog.</summary>
    private bool _uninstallFlowRunning;

    private bool _loaded;

    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public AppsPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
        Loaded += OnLoaded;
    }

    /// <summary>The page's view model.</summary>
    public AppsViewModel ViewModel { get; } = new();

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Reading the uninstall registry is read-only, so it is safe on first show.
        if (_loaded) return;
        _loaded = true;

        try
        {
            await ViewModel.LoadCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            AppLog.Write("Apps page failed to enumerate installed programs.", ex);
        }
    }

    /// <summary>
    /// Confirms, then opens the selected program's own uninstaller.
    /// </summary>
    /// <remarks>
    /// The row comes from the clicked button's <c>DataContext</c> rather than from a selection
    /// property, so the program named in the dialog is necessarily the program acted on. There is no
    /// window between the two in which a selection could move.
    /// </remarks>
    private async void OnUninstallClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: InstalledProgramViewModel row }) return;

        if (_uninstallFlowRunning) return;
        _uninstallFlowRunning = true;

        try
        {
            if (!row.CanUninstall)
            {
                // Belt and braces: the button is hidden in this case, so reaching here means the
                // registry changed under us.
                ViewModel.StatusText = row.NoUninstallerNote;
                return;
            }

            if (await ConfirmAsync(row)) await ViewModel.UninstallAsync(row);
        }
        catch (Exception ex)
        {
            // UninstallAsync handles its own failures; this catches anything unexpected, because an
            // exception escaping an async void handler takes the whole app down.
            AppLog.Write($"Unexpected failure starting the uninstaller for '{row.Name}'.", ex);
        }
        finally
        {
            _uninstallFlowRunning = false;
        }
    }

    /// <summary>
    /// Explains what is about to happen and what Ballast will <em>not</em> do.
    /// </summary>
    private async Task<bool> ConfirmAsync(InstalledProgramViewModel row)
    {
        var body = new StackPanel { Spacing = 10 };

        body.Children.Add(Paragraph(
            $"Windows will now open {row.Name}'s own uninstaller. Anything it asks you — including " +
            "whether to keep your settings or saved files — is its question, not Ballast's."));

        body.Children.Add(Paragraph(
            "Ballast removes nothing itself. It does not delete the program's folder and it does not " +
            "touch the registry. If files are left behind afterwards, Ballast will point them out " +
            "but will not remove them."));

        if (row.Program.InstallLocation is { Length: > 0 } location)
            body.Children.Add(Detail("Installed in", location));

        if (row.Program.Publisher is { Length: > 0 } publisher)
            body.Children.Add(Detail("Publisher", publisher));

        if (row.Program.EstimatedSizeBytes is > 0)
            body.Children.Add(Detail("Reported size", row.SizeText));

        if (row.ShowAdminNote)
        {
            body.Children.Add(Paragraph(
                "This program was installed for all users, so Windows will ask for administrator " +
                "approval before the uninstaller can run."));
        }

        var dialog = new ContentDialog
        {
            // WinUI 3 throws without an explicit XamlRoot.
            XamlRoot = XamlRoot,
            Title = $"Open the uninstaller for {row.Name}?",
            PrimaryButtonText = "Open uninstaller",
            CloseButtonText = "Cancel",

            // Cancel is the default so Return backs out. Nothing here is destructive on its own,
            // but the thing it opens is, and this is the last cheap moment to change your mind.
            DefaultButton = ContentDialogButton.Close,
            Content = new ScrollViewer
            {
                Content = body,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                MaxHeight = 420,
            },
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private static TextBlock Paragraph(string text) => new()
    {
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        MaxWidth = 460,
    };

    /// <summary>A dimmed label with its value, for the facts under the explanation.</summary>
    private static TextBlock Detail(string label, string value)
    {
        var block = new TextBlock { TextWrapping = TextWrapping.Wrap, MaxWidth = 460 };

        block.Inlines.Add(new Run
        {
            Text = label + ": ",
            Foreground = (Microsoft.UI.Xaml.Media.Brush)Application.Current.Resources["AppTextSecondaryBrush"],
        });
        block.Inlines.Add(new Run { Text = value });

        return block;
    }
}
