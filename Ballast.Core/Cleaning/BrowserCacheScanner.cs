using Ballast.Core.Abstractions;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>
/// Clears browser *caches* only.
///
/// This scanner is deliberately built as a strict allowlist of cache folder names. It walks
/// each browser profile and emits only folders whose name appears in <see cref="CacheFolders"/>.
/// History, cookies, saved passwords, bookmarks and site preferences live in sibling files
/// (History, Cookies, Login Data, Bookmarks, Web Data) and are therefore never reachable —
/// signing the user out of their accounts would be a far worse outcome than a full disk.
/// </summary>
public sealed class BrowserCacheScanner : IScanner
{
    public string Name => "Browser caches";

    /// <summary>
    /// Chromium cache directory names. Everything not listed here is left untouched.
    /// </summary>
    private static readonly string[] CacheFolders =
    [
        "Cache",
        "Code Cache",
        "GPUCache",
        "ShaderCache",
        "GrShaderCache",
        "DawnCache",
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        "Service Worker",
    ];

    /// <summary>
    /// Belt-and-braces: even if a cache folder name were ever mistyped into something
    /// sensitive, refuse to emit a path containing any of these.
    /// </summary>
    private static readonly string[] NeverTouch =
    [
        "Login Data", "Cookies", "History", "Bookmarks", "Web Data",
        "Preferences", "Local State", "Sync Data", "Extension",
    ];

    private sealed record Browser(string DisplayName, string UserDataPath, bool IsFirefox = false);

    public Task<ScanResult> ScanAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() =>
        {
            var items = new List<CleanupItem>();
            var skipped = new List<string>();
            long bytes = 0;

            foreach (var browser in DiscoverBrowsers())
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(browser.UserDataPath)) continue;

                var caches = browser.IsFirefox
                    ? FirefoxCaches(browser, skipped, ct)
                    : ChromiumCaches(browser, skipped, ct);

                foreach (var (label, dir) in caches)
                {
                    ct.ThrowIfCancellationRequested();

                    if (NeverTouch.Any(n => dir.Contains(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    if (!PathSafety.IsDeletable(dir)) continue;

                    long size = FileSystemProbe.DirectorySize(dir, skipped, ct);
                    if (size <= 0) continue;

                    items.Add(new CleanupItem
                    {
                        Path = dir,
                        Category = JunkCategory.BrowserCache,
                        SizeBytes = size,
                        IsDirectory = true,
                        Description = label,
                    });

                    bytes += size;
                    progress?.Report(new ScanProgress(dir, items.Count, bytes));
                }
            }

            return new ScanResult { Items = items, SkippedPaths = skipped };
        }, ct);

    private static IEnumerable<Browser> DiscoverBrowsers()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roam = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        yield return new Browser("Microsoft Edge", Path.Combine(local, "Microsoft", "Edge", "User Data"));
        yield return new Browser("Google Chrome", Path.Combine(local, "Google", "Chrome", "User Data"));
        yield return new Browser("Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"));
        yield return new Browser("Firefox", Path.Combine(local, "Mozilla", "Firefox", "Profiles"), IsFirefox: true);
        yield return new Browser("Firefox", Path.Combine(roam, "Mozilla", "Firefox", "Profiles"), IsFirefox: true);
    }

    /// <summary>Chromium keeps one folder per profile ("Default", "Profile 1", ...).</summary>
    private static IEnumerable<(string Label, string Dir)> ChromiumCaches(
        Browser browser, List<string> skipped, CancellationToken ct)
    {
        List<string> profiles = [];

        try
        {
            foreach (var dir in Directory.EnumerateDirectories(browser.UserDataPath))
            {
                var name = Path.GetFileName(dir);
                if (name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                {
                    profiles.Add(dir);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            skipped.Add(browser.UserDataPath);
        }

        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();
            var profileName = Path.GetFileName(profile);

            foreach (var cacheName in CacheFolders)
            {
                var candidate = Path.Combine(profile, cacheName);
                if (!Directory.Exists(candidate)) continue;

                // "Service Worker" holds more than a cache; only its CacheStorage is junk.
                if (cacheName == "Service Worker")
                {
                    foreach (var sub in new[] { "CacheStorage", "ScriptCache" })
                    {
                        var swDir = Path.Combine(candidate, sub);
                        if (Directory.Exists(swDir))
                            yield return ($"{browser.DisplayName} — {profileName} — {sub}", swDir);
                    }
                    continue;
                }

                yield return ($"{browser.DisplayName} — {profileName} — {cacheName}", candidate);
            }
        }
    }

    /// <summary>Firefox stores its HTTP cache in cache2 inside each profile.</summary>
    private static IEnumerable<(string Label, string Dir)> FirefoxCaches(
        Browser browser, List<string> skipped, CancellationToken ct)
    {
        List<string> profiles = [];

        try
        {
            profiles.AddRange(Directory.EnumerateDirectories(browser.UserDataPath));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            skipped.Add(browser.UserDataPath);
        }

        foreach (var profile in profiles)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var sub in new[] { "cache2", "startupCache", "shader-cache" })
            {
                var dir = Path.Combine(profile, sub);
                if (Directory.Exists(dir))
                    yield return ($"Firefox — {Path.GetFileName(profile)} — {sub}", dir);
            }
        }
    }
}
