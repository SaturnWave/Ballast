using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>Which appearance the user picked.</summary>
public enum AppThemePreference
{
    /// <summary>Follow Windows.</summary>
    System,

    /// <summary>Always light.</summary>
    Light,

    /// <summary>Always dark.</summary>
    Dark,
}

/// <summary>One segment in the appearance picker.</summary>
public sealed partial class ThemeOptionViewModel : ObservableObject
{
    private readonly Action<ThemeOptionViewModel>? _onSelected;

    /// <summary>Creates an option.</summary>
    public ThemeOptionViewModel(AppThemePreference value, string label, Action<ThemeOptionViewModel>? onSelected = null)
    {
        Value = value;
        Label = label;
        _onSelected = onSelected;
    }

    /// <summary>The preference this segment represents.</summary>
    public AppThemePreference Value { get; }

    /// <summary>Segment caption.</summary>
    public string Label { get; }

    /// <summary>Bound to the segment's ToggleButton.</summary>
    [ObservableProperty]
    private bool _isSelected;

    partial void OnIsSelectedChanged(bool value)
    {
        if (value) _onSelected?.Invoke(this);
    }
}

/// <summary>
/// Settings. Appearance is applied live to the window's root element and remembered in a one-line
/// text file under <c>%LOCALAPPDATA%\Ballast</c> (an unpackaged app has no
/// <c>ApplicationData.Current</c> to lean on).
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    private static readonly string _settingsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ballast",
        "settings.txt");

    private bool _applying;

    /// <summary>Builds the appearance options and restores the saved preference.</summary>
    public SettingsViewModel()
    {
        // Initializers moved here from the fields: a partial property cannot carry one. Assigning
        // the same value the property already has raises nothing, so no theme is applied or saved.
        Theme = AppThemePreference.System;
        StatusText = string.Empty;

        ThemeOptions.Add(new ThemeOptionViewModel(AppThemePreference.Light, "Light", OnThemeOptionSelected));
        ThemeOptions.Add(new ThemeOptionViewModel(AppThemePreference.Dark, "Dark", OnThemeOptionSelected));
        ThemeOptions.Add(new ThemeOptionViewModel(AppThemePreference.System, "System", OnThemeOptionSelected));

        Theme = Load();
        SyncOptions();
    }

    /// <summary>The three appearance segments.</summary>
    public ObservableCollection<ThemeOptionViewModel> ThemeOptions { get; } = [];

    /// <summary>The active preference.</summary>
    [ObservableProperty]
    private AppThemePreference _theme;

    /// <summary>Transient confirmation text, e.g. "Opened the log folder."</summary>
    [ObservableProperty]
    private string _statusText;

    /// <summary>Product version from the assembly.</summary>
    public string VersionText =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    /// <summary>"Administrator" or "Standard user".</summary>
    public string ElevationText => Elevation.IsElevated ? "Administrator" : "Standard user";

    /// <summary>Where the logs go.</summary>
    public string LogFolder => AppLog.Folder;

    /// <summary>How many junk roots the safety allowlist covers.</summary>
    public string AllowedRootsText => $"{PathSafety.AllowedRoots.Count:N0} locations";

    /// <summary>The allowlist itself, so the user can audit what the app is even willing to touch.</summary>
    public IReadOnlyList<string> AllowedRoots => PathSafety.AllowedRoots;

    /// <summary>The safety promise, shown as the About card's footnote.</summary>
    public string SafetyFootnote =>
        "Ballast deletes only inside the locations listed above, and only after you confirm. " +
        "Scanning never removes anything.";

    /// <summary>Opens the log folder in Explorer.</summary>
    [RelayCommand]
    private void OpenLogFolder()
    {
        try
        {
            string folder = AppLog.EnsureFolder();
            Process.Start(new ProcessStartInfo(folder) { UseShellExecute = true });
            StatusText = "Opened the log folder.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not open the log folder.", ex);
            StatusText = $"Could not open the log folder: {ex.Message}";
        }
    }

    /// <summary>Copies the allowlist to the clipboard-free status line (audit convenience).</summary>
    [RelayCommand]
    private void ShowAllowedRoots() =>
        StatusText = string.Join("  |  ", PathSafety.AllowedRoots);

    partial void OnThemeChanged(AppThemePreference value)
    {
        Apply(value);
        Save(value);
        SyncOptions();
    }

    private void OnThemeOptionSelected(ThemeOptionViewModel option)
    {
        if (_applying) return;

        foreach (ThemeOptionViewModel other in ThemeOptions)
        {
            if (!ReferenceEquals(other, option)) other.IsSelected = false;
        }

        Theme = option.Value;
    }

    private void SyncOptions()
    {
        _applying = true;
        foreach (ThemeOptionViewModel option in ThemeOptions)
            option.IsSelected = option.Value == Theme;
        _applying = false;
    }

    /// <summary>
    /// A WinUI 3 <c>Window</c> is not a <c>FrameworkElement</c>, so the theme is applied to its
    /// root content element instead.
    /// </summary>
    private static void Apply(AppThemePreference preference)
    {
        if (AppRoot.Shell?.Content is not FrameworkElement root) return;

        root.RequestedTheme = preference switch
        {
            AppThemePreference.Light => ElementTheme.Light,
            AppThemePreference.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };
    }

    private static AppThemePreference Load()
    {
        try
        {
            if (!File.Exists(_settingsFile)) return AppThemePreference.System;

            foreach (string line in File.ReadAllLines(_settingsFile))
            {
                int split = line.IndexOf('=');
                if (split <= 0) continue;

                if (!line[..split].Trim().Equals("theme", StringComparison.OrdinalIgnoreCase)) continue;

                if (Enum.TryParse(line[(split + 1)..].Trim(), ignoreCase: true, out AppThemePreference parsed))
                    return parsed;
            }
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not read settings.", ex);
        }

        return AppThemePreference.System;
    }

    private static void Save(AppThemePreference preference)
    {
        try
        {
            string? folder = Path.GetDirectoryName(_settingsFile);
            if (folder is not null) Directory.CreateDirectory(folder);

            File.WriteAllText(_settingsFile, $"theme={preference}{Environment.NewLine}");
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not save settings.", ex);
        }
    }
}
