using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Ballast.App.Controls;
using Ballast.App.ViewModels;
using Ballast.Core.Cleaning;
using Ballast.Core.DiskAnalysis;
using Ballast.Core.Models;
using Ballast.Core.Util;
using Microsoft.UI.Input;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.System;
using Windows.UI.Core;

namespace Ballast.App.Views;

/// <summary>
/// Where the space went: a drive picker, a measured survey, a nested treemap to drill through, and
/// the largest folders and files inside whatever the map is currently showing.
/// </summary>
/// <remarks>
/// <para>
/// The page is the coordinator between <see cref="TreemapControl"/> and
/// <see cref="DiskSpaceViewModel"/>. Both hold a "current folder" and a "selection", and both can
/// change them — the map on a click, the view model on a breadcrumb or list-row click. Each side
/// short-circuits on reference equality, which is what keeps the two in step without a loop.
/// </para>
/// <para>
/// Deleting is the one destructive path, and it cannot be reached without a
/// <see cref="ContentDialog"/> that names the item, states its size, and says where it goes. That
/// dialog defaults to Cancel, so a stray Enter cannot delete anything.
/// </para>
/// <para>
/// There are two of those dialogs, because there are two deletes. The ordinary one moves the item to
/// the Recycle Bin and says so. The permanent one — the extra right-click item, and Shift+Delete on
/// the map, which is what that chord means everywhere else in Windows — bypasses the bin entirely,
/// and gets a <em>different</em> dialog rather than the same one with the verb swapped: its own
/// title, its own danger banner, the risk assessor's verdict on the item, and a primary button that
/// says what it is about to do. A user who has learned to click through the reversible confirmation
/// must not be able to click through this one on the same muscle memory.
/// </para>
/// </remarks>
public sealed partial class DiskSpacePage : Page
{
    // Segoe Fluent Icons code points, built rather than pasted so this file stays plain ASCII.
    private static readonly string _openGlyph = char.ConvertFromUtf32(0xE8B7);   // FolderOpen
    private static readonly string _revealGlyph = char.ConvertFromUtf32(0xEC50); // FileExplorer
    private static readonly string _deleteGlyph = char.ConvertFromUtf32(0xE74D); // Delete
    private static readonly string _warningGlyph = char.ConvertFromUtf32(0xE7BA); // Warning

    /// <summary>
    /// True from the moment a delete flow starts until it finishes. Four controls raise it — the
    /// toolbar button, both of the map's context-menu items, and the Delete key on the map — and
    /// <see cref="DiskSpaceViewModel.CanDelete"/> only goes false once the view model is busy, which
    /// is *after* the confirmation dialog. A second flow starting in that window would ask WinUI to
    /// show a second <see cref="ContentDialog"/> (which throws) and, if it ever stopped throwing,
    /// would confirm the same item twice.
    /// </summary>
    /// <remarks>
    /// One latch covers both kinds of delete deliberately. Two would let a permanent delete be
    /// confirmed while a Recycle Bin delete of the same item was still in flight, and the reversible
    /// one finishing first would leave the permanent one aimed at a path that no longer exists.
    /// </remarks>
    private bool _deleteFlowRunning;

    /// <summary>Builds the page, wires the map to the view model, and sets the data context.</summary>
    public DiskSpacePage()
    {
        InitializeComponent();

        NavigationCacheMode = NavigationCacheMode.Required;

        Treemap.CurrentNodeChanged += OnMapCurrentNodeChanged;
        Treemap.TileSelected += OnMapTileSelected;
        Treemap.TileHovered += OnMapTileHovered;
        Treemap.TileContextRequested += OnMapContextRequested;

        // Subscribed on the map rather than the page, so the Delete key only means "delete the
        // selection" while the map itself has focus. The map's own handler takes Backspace and
        // Escape and leaves everything else to bubble here.
        Treemap.KeyDown += OnMapKeyDown;

        ViewModel.PropertyChanged += OnViewModelPropertyChanged;

        DataContext = ViewModel;
    }

    /// <summary>The page's view model.</summary>
    public DiskSpaceViewModel ViewModel { get; } = new();

    // ============================================================ map -> view model

    private void OnMapCurrentNodeChanged(object? sender, TreemapNodeEventArgs e) =>
        ViewModel.SetCurrentNode(e.Node);

    private void OnMapTileSelected(object? sender, TreemapNodeEventArgs e) =>
        ViewModel.SetSelection(e.Node);

    private void OnMapTileHovered(object? sender, TreemapNodeEventArgs e) =>
        ViewModel.SetHover(e.Node);

    // ============================================================ view model -> map

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            // Assigning Root resets the map to the top of the new tree, which is exactly what a
            // fresh scan (or the rescan after a delete) should do.
            case nameof(DiskSpaceViewModel.TreeRoot):
                Treemap.Root = ViewModel.TreeRoot;
                break;

            // A breadcrumb or list row moved the drill-down; the map has to follow.
            case nameof(DiskSpaceViewModel.CurrentNode):
                Treemap.NavigateTo(ViewModel.CurrentNode);
                break;

            case nameof(DiskSpaceViewModel.SelectedNode):
                Treemap.Select(ViewModel.SelectedNode);
                break;
        }
    }

    // ============================================================ commands

    private void OnRevealClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedNode is { } node) Reveal(node.FullPath);
    }

    private async void OnDeleteClick(object sender, RoutedEventArgs e) =>
        await RunDeleteFlowAsync(permanent: false);

    /// <summary>
    /// Delete removes the selection the reversible way; Shift+Delete removes it permanently, which is
    /// the Windows-wide meaning of that chord. Someone who knows the convention will try it here, and
    /// quietly doing the reversible thing instead would be a worse answer than not listening at all.
    /// </summary>
    private async void OnMapKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key is not VirtualKey.Delete) return;

        // Claimed whatever the flow decides: while the map has focus, Delete belongs to the map, and
        // letting it bubble on to a parent that might grow its own handler later is a trap.
        e.Handled = true;

        await RunDeleteFlowAsync(IsShiftDown());
    }

    private void OnMapContextRequested(object? sender, TreemapContextEventArgs e)
    {
        DirNode node = e.Node;

        // Rebuilt per click rather than cached: it has to reflect the guard's verdict on this node.
        var flyout = new MenuFlyout { XamlRoot = XamlRoot };

        if (node.IsDirectory && node.HasChildren)
        {
            var open = new MenuFlyoutItem
            {
                Text = "Open in the map",
                Icon = new FontIcon { Glyph = _openGlyph },
            };

            open.Click += (_, _) => Treemap.NavigateTo(node);
            flyout.Items.Add(open);
        }

        var reveal = new MenuFlyoutItem
        {
            Text = "Reveal in File Explorer",
            Icon = new FontIcon { Glyph = _revealGlyph },
        };

        reveal.Click += (_, _) => Reveal(node.FullPath);
        flyout.Items.Add(reveal);
        flyout.Items.Add(new MenuFlyoutSeparator());

        // The guard is asked about the tile under the cursor rather than read off the view model.
        // The map selects on right-click, so the two agree today; asking directly means this menu
        // cannot offer a delete for a path the guard has already refused even if they ever stop
        // agreeing. Both items share the verdict, so they can never disagree with each other.
        bool isProtected = SystemPathGuard.IsProtected(node.FullPath, out string? guardReason);
        bool canDelete = ViewModel.CanDelete && !isProtected;

        // A disabled item with no explanation is a dead end, and "why can I not delete this" is the
        // question the guard exists to answer. Its own sentence wins where it has one.
        string refusal =
            isProtected ? guardReason ?? "This path is protected." :
            ViewModel.HasBlockedReason ? ViewModel.BlockedReason :
            ViewModel.IsBusy ? "Wait for the measurement in progress to finish." :
            "Nothing on the map is selected.";

        void Explain(MenuFlyoutItem item)
        {
            if (!item.IsEnabled) ToolTipService.SetToolTip(item, refusal);
        }

        var delete = new MenuFlyoutItem
        {
            Text = "Delete",
            Icon = new FontIcon { Glyph = _deleteGlyph },
            IsEnabled = canDelete,
        };

        Explain(delete);
        delete.Click += async (_, _) => await RunDeleteFlowAsync(permanent: false);
        flyout.Items.Add(delete);

        // Below the ordinary delete, behind a separator, in the danger colour. It is not an
        // equal-weight sibling of the item above it and must not be able to be mistaken for one.
        flyout.Items.Add(new MenuFlyoutSeparator());

        var warning = new FontIcon { Glyph = _warningGlyph };

        var forever = new MenuFlyoutItem
        {
            Text = "Delete permanently",
            Icon = warning,
            IsEnabled = canDelete,
        };

        if (DangerBrush() is { } danger)
        {
            forever.Foreground = danger;
            warning.Foreground = danger;

            // The template's own visual states repaint the text on hover and press, and would take
            // the red away at the exact moment the pointer is over the item and about to click it.
            // Overriding the keys those states read keeps it red throughout. A key that ever stops
            // existing costs nothing here — the item is already red at rest without them.
            forever.Resources["MenuFlyoutItemForeground"] = danger;
            forever.Resources["MenuFlyoutItemForegroundPointerOver"] = danger;
            forever.Resources["MenuFlyoutItemForegroundPressed"] = danger;
        }

        ToolTipService.SetToolTip(forever, "Removes it without using the Recycle Bin. This cannot be undone.");
        Explain(forever);
        forever.Click += async (_, _) => await RunDeleteFlowAsync(permanent: true);
        flyout.Items.Add(forever);

        flyout.ShowAt(Treemap, new FlyoutShowOptions { Position = e.Position });
    }

    private static void Reveal(string path)
    {
        try
        {
            // /select needs the path quoted: Program Files would otherwise arrive as two arguments.
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"")
            {
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            AppLog.Write($"Could not reveal {path} in Explorer.", ex);
        }
    }

    // ============================================================ delete

    /// <summary>
    /// The one delete flow, for both kinds of delete. <paramref name="permanent"/> picks the
    /// confirmation dialog and is handed to the view model; everything protective around it — the
    /// re-entrancy latch, the guard, the identity re-assertion across the dialog — is shared, so the
    /// irreversible path is exactly as careful as the reversible one rather than a looser copy of it.
    /// </summary>
    private async Task RunDeleteFlowAsync(bool permanent)
    {
        if (_deleteFlowRunning) return;
        _deleteFlowRunning = true;

        try
        {
            if (!ViewModel.IsIdle || ViewModel.SelectedNode is not { } target) return;

            // Asked before the dialog, not after it: a confirmation for something that was always
            // going to be refused would teach the user that these dialogs mean nothing. The view
            // model publishes the reason, which the selection bar is already showing.
            if (ViewModel.RefuseIfProtected(target)) return;

            if (!ViewModel.CanDelete) return;

            bool confirmed = permanent
                ? await ConfirmPermanentDeleteAsync(target)
                : await ConfirmDeleteAsync(target);

            if (!confirmed) return;

            // DeleteSelectedAsync deletes whatever SelectedNode holds *when it runs*, not the node
            // named in the dialog the user just read. Nothing about awaiting a modal dialog
            // guarantees those are the same node — a scan finishing, or the map being re-rooted,
            // moves the selection. Deleting something the user was never shown is unforgivable, so
            // the identity is re-asserted here rather than assumed.
            if (!ReferenceEquals(ViewModel.SelectedNode, target))
            {
                AppLog.Write(
                    $"Delete abandoned: the selection changed from {target.FullPath} while the " +
                    "confirmation dialog was open.");
                return;
            }

            CleanReport? report = await ViewModel.DeleteSelectedAsync(permanent);

            // Success is already visible: the status line updates and the map has been re-measured.
            // Only a partial failure needs its own dialog.
            if (report is { Failures.Count: > 0 }) await ShowFailuresAsync(report, permanent);
        }
        catch (Exception ex)
        {
            AppLog.Write("The disk-space delete flow failed.", ex);
        }
        finally
        {
            _deleteFlowRunning = false;
        }
    }

    private async Task<bool> ConfirmDeleteAsync(DirNode target)
    {
        var body = new StackPanel { Spacing = 12 };

        body.Children.Add(Label(target.Name, 17, semibold: true));
        body.Children.Add(Label(target.FullPath, 13, dim: true));

        string what = target.IsDirectory
            ? $"Folder - {target.SizeDisplay} across {target.FileCount:N0} files"
            : $"File - {target.SizeDisplay}";

        body.Children.Add(Label(what, 15));

        body.Children.Add(Label(
            target.IsDirectory
                ? "This folder and everything inside it will be moved to the Recycle Bin. You can " +
                  "restore it from there until the Recycle Bin is emptied."
                : "This file will be moved to the Recycle Bin. You can restore it from there until " +
                  "the Recycle Bin is emptied.",
            14));

        if (ViewModel.HasRiskWarning)
            body.Children.Add(Label(ViewModel.RiskWarning, 14, semibold: true));

        var dialog = new ContentDialog
        {
            // WinUI 3 throws without an explicit XamlRoot.
            XamlRoot = XamlRoot,
            RequestedTheme = ActualTheme,
            Title = "Move to Recycle Bin?",
            PrimaryButtonText = "Move to Recycle Bin",
            CloseButtonText = "Cancel",

            // Cancel is the default, so Enter cannot delete anything.
            DefaultButton = ContentDialogButton.Close,
            Content = Scroll(body),
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    /// <summary>
    /// The confirmation for a permanent delete, and deliberately not the Recycle Bin dialog with the
    /// verb swapped: its own title, a filled danger banner above the item rather than a sentence
    /// below it, the risk assessor's verdict on this exact path, and a primary button that names the
    /// consequence. The one thing it copies is <see cref="ContentDialogButton.Close"/> as the
    /// default, which is load-bearing here in a way it is nowhere else in the app — Return cancels.
    /// </summary>
    private async Task<bool> ConfirmPermanentDeleteAsync(DirNode target)
    {
        Brush? danger = DangerBrush();

        // The same assessor that coloured the tile the user just right-clicked, so the map and this
        // dialog cannot tell them two different stories about the same item.
        RiskAssessment risk = DeletionRiskAssessor.Assess(target.FullPath, target.IsDirectory);

        var body = new StackPanel { Spacing = 12 };

        body.Children.Add(Banner(
            target.IsDirectory
                ? "This folder and everything inside it is erased at once. It does not go to the " +
                  "Recycle Bin, and it cannot be undone."
                : "This file is erased at once. It does not go to the Recycle Bin, and it cannot be undone.",
            danger));

        body.Children.Add(Label(target.Name, 17, semibold: true));
        body.Children.Add(Label(target.FullPath, 13, dim: true));

        body.Children.Add(Label(
            target.IsDirectory
                ? $"Folder - {target.SizeDisplay} across {target.FileCount:N0} files"
                : $"File - {target.SizeDisplay}",
            15));

        body.Children.Add(Label(
            "Nothing in Windows can bring it back afterwards - not the Recycle Bin, not Undo. Only a " +
            "backup you already made would.",
            14));

        body.Children.Add(Label($"{DeletionRiskAssessor.ShortLabel(risk.Level)} - {risk.Title}", 14, semibold: true));
        body.Children.Add(Label(risk.Reason, 14));

        // "Risky or worse". IsAtOrBelow exists so this line does not have to remember that the level
        // numbers run downwards, with 1 the most dangerous.
        if (!DeletionRiskAssessor.IsAtOrBelow(risk.Level, DeletionRisk.Caution))
        {
            body.Children.Add(Label(
                "Deleting this with no undo is very likely to break something that works right now, " +
                "and putting it back could mean reinstalling. If you are not certain what it belongs " +
                "to, cancel and leave it alone.",
                14, semibold: true, brush: danger));
        }

        // The guard's own caution, but only when it is saying something new: the assessor borrows the
        // guard's wording for installed programs, and repeating a sentence makes both count for less.
        if (ViewModel.HasRiskWarning &&
            !string.Equals(ViewModel.RiskWarning, risk.Reason, StringComparison.Ordinal))
        {
            body.Children.Add(Label(ViewModel.RiskWarning, 14, semibold: true));
        }

        var dialog = new ContentDialog
        {
            // WinUI 3 throws without an explicit XamlRoot.
            XamlRoot = XamlRoot,
            RequestedTheme = ActualTheme,
            Title = "Delete permanently? This cannot be undone",
            PrimaryButtonText = "Delete permanently",
            CloseButtonText = "Cancel",

            // Cancel is the default here for the same reason as everywhere else, and it matters more
            // here than anywhere else: a stray Return must not be able to destroy anything.
            DefaultButton = ContentDialogButton.Close,
            Content = Scroll(body),
        };

        // Red rather than accent, so the button the user is about to press does not look like the one
        // they press to agree to harmless things.
        if (Resource<Style>("AppDangerButton") is { } dangerButton) dialog.PrimaryButtonStyle = dangerButton;

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ShowFailuresAsync(CleanReport report, bool permanent)
    {
        var body = new StringBuilder();

        if (report.ItemsDeleted > 0)
            body.AppendLine($"Removed {report.ItemsDeleted:N0} item(s), freeing {ByteFormatter.Format(report.BytesFreed)}.");

        body.AppendLine($"{report.Failures.Count:N0} could not be removed:");
        body.AppendLine();

        foreach (CleanFailure failure in report.Failures.Take(20))
            body.AppendLine($"{failure.Path}{Environment.NewLine}    {failure.Reason}{Environment.NewLine}");

        if (report.Failures.Count > 20)
            body.AppendLine($"and {report.Failures.Count - 20:N0} more (see the log folder).");

        // Core marks the failures a permanent delete would actually fix - too large for the bin, or a
        // volume that has none. Naming the way out beats leaving the user to guess it.
        if (!permanent && report.Failures.Any(
                failure => failure.Reason.Contains(UserFileDeleter.PermanentDeleteHint, StringComparison.Ordinal)))
        {
            body.AppendLine();
            body.AppendLine(
                "Right-click the item on the map and choose \"Delete permanently\" to remove " +
                "it without the Recycle Bin. That cannot be undone.");
        }

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            RequestedTheme = ActualTheme,
            Title = "Not everything could be removed",
            CloseButtonText = "OK",
            DefaultButton = ContentDialogButton.Close,
            Content = Scroll(Label(body.ToString().TrimEnd(), 14)),
        };

        await dialog.ShowAsync();
    }

    /// <summary>
    /// The banner across the top of the permanent-delete dialog: a filled danger panel, which nothing
    /// else in this page's dialogs has. It is the first thing read, and it is the thing the ordinary
    /// Recycle Bin dialog cannot be mistaken for.
    /// </summary>
    private Border Banner(string text, Brush? danger)
    {
        var row = new Grid { ColumnSpacing = 10 };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var icon = new FontIcon
        {
            Glyph = _warningGlyph,
            FontSize = 18,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 1, 0, 0),
        };

        TextBlock caption = Label(text, 14, semibold: true, brush: danger);

        Grid.SetColumn(icon, 0);
        Grid.SetColumn(caption, 1);
        row.Children.Add(icon);
        row.Children.Add(caption);

        var panel = new Border
        {
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 10, 12, 12),
            Child = row,
        };

        if (danger is not null)
        {
            icon.Foreground = danger;
            panel.BorderBrush = danger;
        }

        // Filled where the tint resolves, outlined where it does not. Either way the panel is there,
        // and the panel is the thing the Recycle Bin dialog does not have.
        if (Resource<Brush>("AppDangerSubtleBrush") is { } tint) panel.Background = tint;

        return panel;
    }

    /// <summary>Wraps dialog content so a long path or a long failure list cannot outgrow the dialog.</summary>
    private static ScrollViewer Scroll(UIElement content) => new()
    {
        Content = content,
        MaxHeight = 340,
        HorizontalScrollMode = ScrollMode.Disabled,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
    };

    /// <summary>The design system's danger brush for this page's theme, or null if it is missing.</summary>
    private Brush? DangerBrush() => Resource<Brush>("AppDangerBrush");

    /// <summary>
    /// A design-system resource, resolved for this page's <see cref="FrameworkElement.ActualTheme"/>,
    /// or null when it is not there. Never throws.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Content built in code cannot use <c>{ThemeResource}</c>, so App.xaml's dictionaries are walked
    /// by hand — and deliberately not through <c>Application.Current.Resources[key]</c>, which
    /// answers for the <em>application's</em> theme. Every dialog here follows the page's
    /// <c>ActualTheme</c>, and the Settings page sets <c>RequestedTheme</c> on the shell's root
    /// element, so the two genuinely come apart: ask the wrong one and dark theme's pale danger red
    /// (#F2857C) lands on a white dialog at roughly 2.4:1, on the one dialog in this app that has to
    /// be read rather than skimmed. The walk is also indifferent to whether a bare key lookup reaches
    /// into merged and theme dictionaries, which is not a thing to be guessing about here.
    /// </para>
    /// <para>
    /// Later merges win, matching XAML's own precedence. Theme dictionaries are consulted before the
    /// dictionary they hang off, so a themed token beats an unthemed one of the same name. High
    /// contrast is not told apart from light and dark — the cost of that is the design system's own
    /// red instead of a system colour, and every caller treats a miss as "no colour" rather than
    /// inventing one, so nothing here can end up unreadable.
    /// </para>
    /// </remarks>
    private T? Resource<T>(string key) where T : class
    {
        if (Application.Current?.Resources is not { } root) return null;

        string themeName = ActualTheme == ElementTheme.Dark ? "Dark" : "Light";

        try
        {
            for (int i = root.MergedDictionaries.Count - 1; i >= 0; i--)
            {
                ResourceDictionary dictionary = root.MergedDictionaries[i];

                if (dictionary.ThemeDictionaries.TryGetValue(themeName, out object? themed) &&
                    themed is ResourceDictionary themedDictionary &&
                    themedDictionary.TryGetValue(key, out object? themedValue) &&
                    themedValue is T themedMatch)
                {
                    return themedMatch;
                }

                if (dictionary.TryGetValue(key, out object? value) && value is T match) return match;
            }

            return root.TryGetValue(key, out object? own) ? own as T : null;
        }
        catch (Exception)
        {
            // A dictionary still being merged is not worth failing a confirmation dialog over.
            return null;
        }
    }

    /// <summary>
    /// True while either Shift key is held. Read from the input source at the moment the key arrives,
    /// because <see cref="KeyRoutedEventArgs"/> carries no modifier state of its own.
    /// </summary>
    private static bool IsShiftDown() =>
        (InputKeyboardSource.GetKeyStateForCurrentThread(VirtualKey.Shift) & CoreVirtualKeyStates.Down)
            == CoreVirtualKeyStates.Down;

    private static TextBlock Label(
        string text, double size, bool semibold = false, bool dim = false, Brush? brush = null)
    {
        var label = new TextBlock
        {
            Text = text,
            FontSize = size,
            FontWeight = semibold ? FontWeights.SemiBold : FontWeights.Normal,
            Opacity = dim ? 0.65 : 1d,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
        };

        // Assigned only when asked for: writing null would replace the inherited foreground rather
        // than leave it alone.
        if (brush is not null) label.Foreground = brush;

        return label;
    }
}
