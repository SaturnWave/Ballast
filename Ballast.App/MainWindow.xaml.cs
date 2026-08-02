using System.Runtime.InteropServices;
using Ballast.App.Views;
using Ballast.Core.Util;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;

namespace Ballast.App;

/// <summary>
/// The app shell: a quiet sidebar, a custom title bar, and a <see cref="Frame"/> hosting the
/// five pages.
/// </summary>
public sealed partial class MainWindow : Window
{
    private const int DefaultWidthDip = 1100;
    private const int DefaultHeightDip = 760;
    private const int MinimumWidthDip = 860;
    private const int MinimumHeightDip = 620;

    private nint _hwnd;
    private nint _originalWndProc;
    private WndProc? _wndProcKeepAlive;

    /// <summary>Builds the shell and applies the window chrome.</summary>
    public MainWindow()
    {
        InitializeComponent();

        Instance = this;
        Title = "Ballast";

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        ElevationBadge.Text = Elevation.IsElevated ? "Administrator" : "Standard user";

        ConfigureWindow();
    }

    /// <summary>
    /// The live shell, so pages can ask for navigation without a messaging bus. Named
    /// <c>Instance</c> rather than <c>Current</c> so it does not shadow the static
    /// <see cref="Window.Current"/> the framework already defines.
    /// </summary>
    public static MainWindow? Instance { get; private set; }

    /// <summary>
    /// Selects a sidebar entry by tag and navigates to it. Tags are
    /// <c>dashboard</c>, <c>cleanup</c>, <c>diskspace</c>, <c>startup</c>, <c>settings</c>.
    /// </summary>
    public void NavigateTo(string tag)
    {
        NavigationViewItem? target = NavView.MenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(i => string.Equals(i.Tag as string, tag, StringComparison.OrdinalIgnoreCase));

        if (target is null) return;

        // Assigning SelectedItem raises SelectionChanged, which performs the navigation.
        if (!ReferenceEquals(NavView.SelectedItem, target))
        {
            NavView.SelectedItem = target;
        }
        else
        {
            Navigate(tag, null);
        }
    }

    private void OnNavViewLoaded(object sender, RoutedEventArgs e)
    {
        if (NavView.SelectedItem is null) NavView.SelectedItem = DashboardItem;
    }

    private void OnNavViewSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item) return;
        Navigate(item.Tag as string, args.RecommendedNavigationTransitionInfo);
    }

    private void Navigate(string? tag, NavigationTransitionInfo? transition)
    {
        Type page = tag switch
        {
            "cleanup" => typeof(CleanupPage),
            "diskspace" => typeof(DiskSpacePage),
            "apps" => typeof(AppsPage),
            "startup" => typeof(StartupPage),
            "security" => typeof(SecurityPage),
            "settings" => typeof(SettingsPage),
            "help" => typeof(HelpPage),
            _ => typeof(DashboardPage),
        };

        if (ContentFrame.CurrentSourcePageType == page) return;

        ContentFrame.Navigate(page, null, transition ?? new EntranceNavigationTransitionInfo());
    }

    // =====================================================================================
    // Window chrome. AppWindow can set a size but has no minimum-size API, so the minimum is
    // enforced by handling WM_GETMINMAXINFO through a window-procedure subclass.
    // =====================================================================================

    private void ConfigureWindow()
    {
        try
        {
            _hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

            double scale = GetDpiForWindow(_hwnd) / 96.0;
            if (scale <= 0) scale = 1.0;

            AppWindow appWindow = AppWindow.GetFromWindowId(Win32Interop.GetWindowIdFromWindow(_hwnd));

            appWindow.Resize(new Windows.Graphics.SizeInt32(
                (int)(DefaultWidthDip * scale),
                (int)(DefaultHeightDip * scale)));

            // The caption buttons sit directly on the page background rather than on a strip
            // of their own, so the title bar stops reading as a separate band of chrome.
            appWindow.TitleBar.ButtonBackgroundColor = Colors.Transparent;
            appWindow.TitleBar.ButtonInactiveBackgroundColor = Colors.Transparent;

            HookMinimumSize();
        }
        catch (Exception ex)
        {
            // A cosmetic failure here must not stop the app from opening.
            AppLog.Write("Could not apply the window chrome.", ex);
        }
    }

    private void HookMinimumSize()
    {
        _wndProcKeepAlive = WindowProc;

        nint pointer = Marshal.GetFunctionPointerForDelegate(_wndProcKeepAlive);
        _originalWndProc = SetWindowLongPtrW(_hwnd, GwlpWndProc, pointer);

        if (_originalWndProc == 0)
        {
            // Subclassing failed; drop the delegate so we do not leak a dangling callback.
            _wndProcKeepAlive = null;
        }
    }

    private nint WindowProc(nint hwnd, uint message, nint wParam, nint lParam)
    {
        if (message == WmGetMinMaxInfo && lParam != 0)
        {
            double scale = GetDpiForWindow(hwnd) / 96.0;
            if (scale <= 0) scale = 1.0;

            MinMaxInfo info = Marshal.PtrToStructure<MinMaxInfo>(lParam);
            info.MinTrackSize.X = (int)(MinimumWidthDip * scale);
            info.MinTrackSize.Y = (int)(MinimumHeightDip * scale);
            Marshal.StructureToPtr(info, lParam, fDeleteOld: false);
        }

        return CallWindowProcW(_originalWndProc, hwnd, message, wParam, lParam);
    }

    private const int GwlpWndProc = -4;
    private const uint WmGetMinMaxInfo = 0x0024;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint WndProc(nint hwnd, uint message, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MinMaxInfo
    {
        public NativePoint Reserved;
        public NativePoint MaxSize;
        public NativePoint MaxPosition;
        public NativePoint MinTrackSize;
        public NativePoint MaxTrackSize;
    }

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern nint SetWindowLongPtrW(nint hwnd, int index, nint newLong);

    [DllImport("user32.dll", EntryPoint = "CallWindowProcW")]
    private static extern nint CallWindowProcW(nint previous, nint hwnd, uint message, nint wParam, nint lParam);

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(nint hwnd);
}
