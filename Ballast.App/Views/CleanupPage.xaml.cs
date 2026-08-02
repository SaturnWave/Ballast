using System.Text;
using Ballast.App.ViewModels;
using Ballast.Core.Models;
using Ballast.Core.Util;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Ballast.App.Views;

/// <summary>
/// The primary feature page: scan, review by category, then delete.
/// </summary>
/// <remarks>
/// The Clean button never deletes directly. It opens a <see cref="ContentDialog"/> that itemises
/// the categories, counts and sizes about to be removed; only a <c>Primary</c> result reaches
/// <see cref="CleanupViewModel.CleanAsync"/>.
/// </remarks>
public sealed partial class CleanupPage : Page
{
    /// <summary>Builds the page and wires the view model as its data context.</summary>
    public CleanupPage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;
        DataContext = ViewModel;
    }

    /// <summary>The page's view model.</summary>
    public CleanupViewModel ViewModel { get; } = new();

    private async void OnCleanClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!ViewModel.CanClean) return;

            bool confirmed = await ConfirmAsync();
            if (!confirmed) return;

            CleanReport? report = await ViewModel.CleanAsync();
            if (report is not null) await ShowReportAsync(report);
        }
        catch (Exception ex)
        {
            AppLog.Write("The clean confirmation flow failed.", ex);
        }
    }

    private async Task<bool> ConfirmAsync()
    {
        var dialog = new ContentDialog
        {
            // WinUI 3 throws without an explicit XamlRoot.
            XamlRoot = XamlRoot,
            RequestedTheme = ActualTheme,
            Title = "Remove these files?",
            PrimaryButtonText = "Remove",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            Content = BuildBody(
                "This cannot be undone. Ballast only ever deletes inside its allowed cleanup " +
                "locations, and only the items listed here.",
                ViewModel.BuildConfirmationSummary()),
        };

        ContentDialogResult result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary;
    }

    private async Task ShowReportAsync(CleanReport report)
    {
        var body = new StringBuilder();
        body.AppendLine($"Reclaimed {ByteFormatter.Format(report.BytesFreed)}.");
        body.AppendLine($"Removed {report.ItemsDeleted:N0} items.");

        if (report.Failures.Count > 0)
        {
            body.AppendLine();
            body.AppendLine($"{report.Failures.Count:N0} could not be removed:");

            foreach (CleanFailure failure in report.Failures.Take(20))
                body.AppendLine($"  {failure.Path} - {failure.Reason}");

            if (report.Failures.Count > 20)
                body.AppendLine($"  and {report.Failures.Count - 20:N0} more (see the log folder).");
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            RequestedTheme = ActualTheme,
            Title = report.Failures.Count == 0 ? "Done" : "Done, with skips",
            CloseButtonText = "OK",
            DefaultButton = ContentDialogButton.Close,
            Content = BuildBody(null, body.ToString().TrimEnd()),
        };

        await dialog.ShowAsync();
    }

    private static FrameworkElement BuildBody(string? caption, string detail)
    {
        // Sizes and line heights match the type ramp in Styles/Typography.xaml; a dialog built
        // in code should not be the one place in the app running on Fluent defaults.
        var panel = new StackPanel { Spacing = 12 };

        if (!string.IsNullOrWhiteSpace(caption))
        {
            panel.Children.Add(new TextBlock
            {
                Text = caption,
                FontSize = 13,
                LineHeight = 19,
                TextWrapping = TextWrapping.Wrap,
            });
        }

        panel.Children.Add(new TextBlock
        {
            Text = detail,
            FontSize = 14,
            LineHeight = 20,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
        });

        return new ScrollViewer
        {
            Content = panel,
            MaxHeight = 340,
            HorizontalScrollMode = ScrollMode.Disabled,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        };
    }
}
