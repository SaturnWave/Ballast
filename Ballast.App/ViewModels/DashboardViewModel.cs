using Ballast.Core.DiskAnalysis;
using Ballast.Core.Models;
using Ballast.Core.Startup;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AppRoot = Ballast.App.App;

namespace Ballast.App.ViewModels;

/// <summary>
/// The landing page. Runs a Smart Scan (the same read-only coordinator the Cleanup page uses) and
/// summarises the three things worth knowing: reclaimable junk, drive pressure, startup load.
/// </summary>
public sealed partial class DashboardViewModel : ScanViewModelBase
{
    /// <summary>Reads the cheap drive facts immediately; junk and startup need a pass.</summary>
    public DashboardViewModel()
    {
        // Initializers moved here from the fields: a partial property cannot carry one.
        DriveName = "This PC";
        DriveSubtitle = string.Empty;
        DriveFreeDisplay = "-";

        RefreshDrive();
        StatusText = "Run a Smart Scan to see what can be reclaimed.";
    }

    /// <summary>Bytes the last Smart Scan found.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(JunkDisplay))]
    [NotifyPropertyChangedFor(nameof(JunkRowValue))]
    private long _junkBytes;

    /// <summary>Items the last Smart Scan found.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(JunkSubtitle))]
    private int _junkItems;

    /// <summary>True once a Smart Scan has completed.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HeroCaption))]
    [NotifyPropertyChangedFor(nameof(JunkRowValue))]
    private bool _hasScanned;

    /// <summary>Label-first drive title, e.g. "Windows (C:)".</summary>
    [ObservableProperty]
    private string _driveName;

    /// <summary>"312 GB of 931 GB used".</summary>
    [ObservableProperty]
    private string _driveSubtitle;

    /// <summary>Percentage of the system drive in use, 0-100.</summary>
    [ObservableProperty]
    private double _drivePercent;

    /// <summary>Formatted free space, shown as the row's trailing value.</summary>
    [ObservableProperty]
    private string _driveFreeDisplay;

    /// <summary>How many programs launch with Windows.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StartupSubtitle))]
    private int _startupCount;

    /// <summary>How many of those are currently enabled.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StartupSubtitle))]
    private int _startupEnabledCount;

    /// <summary>The big number in the hero card.</summary>
    public string JunkDisplay => ByteFormatter.Format(JunkBytes);

    /// <summary>Secondary line under the hero number.</summary>
    public string JunkSubtitle => JunkItems == 0
        ? "No junk found yet"
        : $"across {JunkItems:N0} items";

    /// <summary>Explains the hero card before and after a scan.</summary>
    public string HeroCaption => HasScanned
        ? "Reviewed and ready. Nothing is removed until you say so."
        : "Smart Scan only reads. You choose what goes.";

    /// <summary>Trailing value for the junk summary row.</summary>
    public string JunkRowValue => HasScanned ? ByteFormatter.Format(JunkBytes) : "Not scanned";

    /// <summary>"12 of 19 enabled".</summary>
    public string StartupSubtitle => StartupCount == 0
        ? "Nothing launches with Windows"
        : $"{StartupEnabledCount:N0} of {StartupCount:N0} enabled";

    /// <summary>True when the process has administrator rights.</summary>
    public bool IsElevated => Elevation.IsElevated;

    /// <summary>Footnote about elevation.</summary>
    public string ElevationNote => Elevation.IsElevated
        ? "Running as administrator: system-wide caches are included."
        : "Running as a standard user. System-wide caches are listed but skipped.";

    /// <summary>Read-only sweep of every junk source, then refresh the summary rows.</summary>
    [RelayCommand]
    private async Task SmartScanAsync()
    {
        if (IsBusy) return;

        CancellationToken ct = BeginOperation("Smart Scan running...");
        IProgress<ScanProgress> progress = CreateProgress(ApplyProgress);

        try
        {
            ScanResult result = await Task.Run(
                () => AppRoot.Services.ScanCoordinator.ScanAllAsync(progress, ct), ct);

            JunkBytes = result.TotalBytes;
            JunkItems = result.Count;
            HasScanned = true;

            StatusText = result.Count == 0
                ? "Nothing to reclaim."
                : $"{ByteFormatter.Format(result.TotalBytes)} can be reclaimed.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Smart Scan cancelled.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Smart Scan failed.", ex);
            StatusText = $"Smart Scan failed: {ex.Message}";
        }
        finally
        {
            EndOperation();
        }

        await RefreshAsync();
    }

    /// <summary>
    /// Re-reads the cheap facts: the system drive and the fast half of the startup inventory
    /// (registry keys and Startup folders only - scheduled tasks are the Startup page's business).
    /// </summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        RefreshDrive();

        try
        {
            IReadOnlyList<StartupEntry> entries = await AppRoot.Services.Startup.ScanFastAsync();
            StartupCount = entries.Count;
            StartupEnabledCount = entries.Count(e => e.IsEnabled);
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not count startup entries for the dashboard.", ex);
            StartupCount = 0;
            StartupEnabledCount = 0;
        }
    }

    private void RefreshDrive()
    {
        try
        {
            IReadOnlyList<DriveSummary> drives = AppRoot.Services.Drives.GetFixedDrives();
            if (drives.Count == 0)
            {
                DriveName = "This PC";
                DriveSubtitle = "No local drives available";
                DrivePercent = 0;
                DriveFreeDisplay = "-";
                return;
            }

            string? systemRoot = SafeSystemRoot();

            DriveSummary drive = drives.FirstOrDefault(
                d => string.Equals(d.RootPath, systemRoot, StringComparison.OrdinalIgnoreCase))
                ?? drives[0];

            DriveName = drive.DisplayName;
            DriveSubtitle = $"{drive.UsedDisplay} of {drive.TotalDisplay} used";
            DrivePercent = drive.UsedFraction * 100d;
            DriveFreeDisplay = $"{drive.FreeDisplay} free";
        }
        catch (Exception ex)
        {
            AppLog.Write("Could not read the system drive.", ex);
            DriveName = "This PC";
            DriveSubtitle = "Drive unavailable";
            DrivePercent = 0;
            DriveFreeDisplay = "-";
        }
    }

    private static string? SafeSystemRoot()
    {
        try { return Path.GetPathRoot(Environment.SystemDirectory); }
        catch { return null; }
    }
}
