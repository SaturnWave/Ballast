namespace Ballast.Core.Util;

/// <summary>
/// The guard rail for every destructive operation.
///
/// Nothing in this app deletes a path unless <see cref="IsDeletable"/> returns true for it.
/// The rule is an allowlist: a path must sit underneath one of the roots we explicitly
/// registered as junk. A denylist would be unsafe — one missed entry means data loss.
/// </summary>
public static class PathSafety
{
    private static readonly string[] _allowedRoots = BuildAllowedRoots();

    /// <summary>Roots we will never descend into or delete, even if some caller asks.</summary>
    private static readonly string[] _forbidden = BuildForbidden();

    /// <summary>
    /// Defence in depth. Browser profile folders have to be allowed roots so their caches can be
    /// cleared, which means a bug in a scanner could otherwise reach the files holding saved
    /// passwords, cookies and history. Signing a user out of every website — or losing their
    /// browsing history — would be far worse than leaving a full disk, so these file names are
    /// rejected unconditionally, no matter which scanner asks.
    /// </summary>
    private static readonly string[] _sensitiveFileNames =
    [
        // Chromium family
        "Login Data", "Login Data For Account", "Cookies", "History", "Bookmarks",
        "Web Data", "Local State", "Preferences", "Secure Preferences", "Affiliation Database",
        // Firefox
        "key3.db", "key4.db", "logins.json", "cert9.db", "cert8.db",
        "places.sqlite", "formhistory.sqlite", "signons.sqlite", "cookies.sqlite",
        "prefs.js", "sessionstore.jsonlz4",
    ];

    public static IReadOnlyList<string> AllowedRoots => _allowedRoots;

    private static string[] BuildAllowedRoots()
    {
        var local  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roam   = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var win    = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var roots = new List<string?>
        {
            Path.GetTempPath(),                                   // %TEMP%
            Path.Combine(win, "Temp"),                            // C:\Windows\Temp
            Path.Combine(win, "SoftwareDistribution", "Download"), // Update cache
            Path.Combine(local, "Temp"),
            Path.Combine(local, "Microsoft", "Windows", "Explorer"),        // thumbcache
            Path.Combine(local, "Microsoft", "Windows", "INetCache"),
            Path.Combine(local, "CrashDumps"),
            Path.Combine(local, "Microsoft", "Edge", "User Data"),
            Path.Combine(local, "Google", "Chrome", "User Data"),
            Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"),
            Path.Combine(roam,  "Mozilla", "Firefox", "Profiles"),
            Path.Combine(local, "Mozilla", "Firefox", "Profiles"),
        };

        return roots
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => Normalize(r!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] BuildForbidden()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var list = new List<string>
        {
            Normalize(win),
            Normalize(Environment.GetFolderPath(Environment.SpecialFolder.System)),
            Normalize(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)),
            Normalize(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)),
            Normalize(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
            Normalize(Path.Combine(win, "System32")),
            Normalize(Path.Combine(win, "SysWOW64")),
        };
        return list.Where(p => p.Length > 3).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string Normalize(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return path;
        }
    }

    /// <summary>
    /// True only when <paramref name="path"/> is strictly inside one of the allowed junk roots.
    /// An exact match against a root is rejected: we clear a root's <em>contents</em>,
    /// never the root itself.
    /// </summary>
    public static bool IsDeletable(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        string full;
        try { full = Normalize(path); }
        catch { return false; }

        // Refuse a bare drive root such as "C:\".
        if (full.Length <= 3) return false;

        // Never delete one of the protected roots itself.
        if (_forbidden.Any(f => full.Equals(f, StringComparison.OrdinalIgnoreCase)))
            return false;

        // Never delete a known credential/history store, wherever it lives.
        var leaf = Path.GetFileName(full);
        if (leaf.Length > 0 &&
            _sensitiveFileNames.Contains(leaf, StringComparer.OrdinalIgnoreCase))
            return false;

        foreach (var root in _allowedRoots)
        {
            if (full.Equals(root, StringComparison.OrdinalIgnoreCase))
                return false; // the root itself stays

            if (full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>Throws unless the path passes <see cref="IsDeletable"/>.</summary>
    public static void EnsureDeletable(string path)
    {
        if (!IsDeletable(path))
            throw new InvalidOperationException(
                $"Refusing to delete '{path}': it is outside the allowed cleanup locations.");
    }
}
