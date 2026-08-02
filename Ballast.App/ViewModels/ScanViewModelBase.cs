using System.Diagnostics;
using Ballast.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;

namespace Ballast.App.ViewModels;

/// <summary>
/// Shared plumbing for every page that runs a long operation: one
/// <see cref="CancellationTokenSource"/> per run, a <see cref="Cancel"/> command, and an
/// <see cref="IProgress{T}"/> factory that marshals reports back to the UI thread and throttles
/// them (scanners report per item, which is far more often than a UI can usefully repaint).
/// </summary>
public abstract partial class ScanViewModelBase : ObservableObject
{
    private readonly DispatcherQueue? _dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    private TimeSpan _lastReport = TimeSpan.MinValue;
    private CancellationTokenSource? _cts;

    /// <summary>Seeds the resting state of the progress surface.</summary>
    protected ScanViewModelBase()
    {
        // Initializers moved here from the fields: a partial property cannot carry one.
        CurrentPath = string.Empty;
        StatusText = string.Empty;
        IsIndeterminate = true;
    }

    /// <summary>True while a scan or clean is in flight.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;

    /// <summary>The path the operation is currently looking at. Shown under the progress bar.</summary>
    [ObservableProperty]
    private string _currentPath;

    /// <summary>One-line human summary of what just happened.</summary>
    [ObservableProperty]
    private string _statusText;

    /// <summary>0-100. Only meaningful when <see cref="IsIndeterminate"/> is false.</summary>
    [ObservableProperty]
    private double _progressValue;

    /// <summary>Most scanners cannot know their total up front, so this defaults to true.</summary>
    [ObservableProperty]
    private bool _isIndeterminate;

    /// <summary>Convenience inverse of <see cref="IsBusy"/> for enabling controls.</summary>
    public bool IsIdle => !IsBusy;

    /// <summary>Cancels the in-flight operation, if any. Safe to call when idle.</summary>
    [RelayCommand]
    protected void Cancel()
    {
        try { _cts?.Cancel(); }
        catch (ObjectDisposedException) { /* already finished */ }
    }

    /// <summary>
    /// Starts a fresh operation: cancels anything still running, resets the progress surface and
    /// returns the token the new work must observe.
    /// </summary>
    protected CancellationToken BeginOperation(string status)
    {
        Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();

        _lastReport = TimeSpan.MinValue;
        IsBusy = true;
        IsIndeterminate = true;
        ProgressValue = 0;
        CurrentPath = string.Empty;
        StatusText = status;

        return _cts.Token;
    }

    /// <summary>Clears the busy flag and the transient progress text.</summary>
    protected void EndOperation()
    {
        IsBusy = false;
        CurrentPath = string.Empty;
        ProgressValue = 0;
        IsIndeterminate = true;
    }

    /// <summary>
    /// Wraps <paramref name="onReport"/> in a UI-thread-marshalling, time-throttled
    /// <see cref="IProgress{T}"/>. Create this on the UI thread.
    /// </summary>
    protected IProgress<ScanProgress> CreateProgress(
        Action<ScanProgress> onReport,
        TimeSpan? minimumInterval = null)
    {
        TimeSpan interval = minimumInterval ?? TimeSpan.FromMilliseconds(66);

        return new Progress<ScanProgress>(report =>
        {
            TimeSpan now = _clock.Elapsed;
            if (_lastReport != TimeSpan.MinValue && now - _lastReport < interval) return;
            _lastReport = now;

            Post(() => onReport(report));
        });
    }

    /// <summary>Runs <paramref name="action"/> on the UI thread, inline when already there.</summary>
    protected void Post(Action action)
    {
        if (_dispatcher is null || _dispatcher.HasThreadAccess)
        {
            action();
            return;
        }

        _dispatcher.TryEnqueue(() => action());
    }

    /// <summary>Applies a scan progress ticket to the standard progress surface.</summary>
    protected void ApplyProgress(ScanProgress report)
    {
        CurrentPath = report.CurrentPath;

        if (report.Fraction is { } fraction)
        {
            IsIndeterminate = false;
            ProgressValue = Math.Clamp(fraction * 100d, 0d, 100d);
        }
    }
}
