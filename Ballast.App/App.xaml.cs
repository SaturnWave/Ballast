using Ballast.Core.Cleaning;
using Ballast.Core.DiskAnalysis;
using Ballast.Core.Startup;
using Microsoft.UI.Xaml;

namespace Ballast.App;

/// <summary>
/// Application entry point. Creates the single top-level <see cref="MainWindow"/> and
/// exposes the hand-rolled service locator the view models pull from.
/// </summary>
public partial class App : Application
{
    /// <summary>Initialises the app and hooks the last-chance exception logger.</summary>
    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    /// <summary>
    /// The one and only window. Named <c>Shell</c> rather than <c>MainWindow</c> so it does not
    /// shadow the <see cref="MainWindow"/> type inside this namespace.
    /// </summary>
    public static Window? Shell { get; private set; }

    /// <summary>The app's service locator. Deliberately not a DI container.</summary>
    public static AppServices Services => AppServices.Current;

    /// <inheritdoc />
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var window = new MainWindow();
        Shell = window;
        window.Activate();

        // A second launch is handled entirely in Program.cs, which finds this window and
        // foregrounds it from the outside before exiting. Nothing to hook here.
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        AppLog.Write("Unhandled exception on the UI thread.", e.Exception);

        // Deleting is always gated behind an explicit confirmation, so a UI-layer fault can never
        // have destroyed anything. Keep the window alive and leave the evidence in the log folder
        // (Settings has a shortcut to it) rather than dropping the user out of the app.
        e.Handled = true;
    }
}

/// <summary>
/// A deliberately tiny service locator: a lock-protected <see cref="Dictionary{TKey,TValue}"/>
/// of lazily constructed singletons. No DI container, no attributes, no magic - every service
/// that exists is spelled out as a property below.
/// </summary>
public sealed class AppServices
{
    private static readonly Lazy<AppServices> _current = new(() => new AppServices());

    private readonly Dictionary<Type, object> _singletons = [];
    private readonly object _gate = new();

    private AppServices() { }

    /// <summary>The process-wide instance.</summary>
    public static AppServices Current => _current.Value;

    /// <summary>Runs every registered junk scanner and merges their results. Never deletes.</summary>
    public JunkScanCoordinator ScanCoordinator => Get(static () => new JunkScanCoordinator());

    /// <summary>The only component in the app that is allowed to delete anything.</summary>
    public CleaningService Cleaner => Get(static () => new CleaningService());

    /// <summary>Read-only enumeration of everything Windows launches at sign-in.</summary>
    public StartupScanner Startup => Get(static () => new StartupScanner());

    /// <summary>Reversible enable/disable for startup entries. Moves, never deletes.</summary>
    public StartupToggleService StartupToggle => Get(static () => new StartupToggleService());

    /// <summary>Measures a directory tree. Stateless, so the Core's shared instance is fine.</summary>
    public DirectoryTreeScanner TreeScanner => DirectoryTreeScanner.Shared;

    /// <summary>Lists the local fixed disks worth analysing.</summary>
    public DriveInfoProvider Drives => DriveInfoProvider.Shared;

    private T Get<T>(Func<T> factory) where T : class
    {
        lock (_gate)
        {
            if (_singletons.TryGetValue(typeof(T), out var existing))
                return (T)existing;

            T created = factory();
            _singletons[typeof(T)] = created;
            return created;
        }
    }
}

/// <summary>
/// Append-only text log under <c>%LOCALAPPDATA%\Ballast\logs</c>. Never throws: a failure to
/// log must not become a failure of the operation being logged.
/// </summary>
public static class AppLog
{
    /// <summary>Directory the Settings page opens.</summary>
    public static string Folder { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ballast",
        "logs");

    /// <summary>Ensures <see cref="Folder"/> exists and returns it.</summary>
    public static string EnsureFolder()
    {
        try { Directory.CreateDirectory(Folder); } catch { /* best effort */ }
        return Folder;
    }

    /// <summary>Writes one timestamped line, plus the exception detail when supplied.</summary>
    public static void Write(string message, Exception? ex = null)
    {
        try
        {
            EnsureFolder();
            string file = Path.Combine(Folder, $"Ballast-{DateTime.Now:yyyy-MM-dd}.log");
            string line = ex is null
                ? $"{DateTime.Now:HH:mm:ss}  {message}{Environment.NewLine}"
                : $"{DateTime.Now:HH:mm:ss}  {message}{Environment.NewLine}{ex}{Environment.NewLine}";
            File.AppendAllText(file, line);
        }
        catch
        {
            // Logging is best effort by design.
        }
    }
}
