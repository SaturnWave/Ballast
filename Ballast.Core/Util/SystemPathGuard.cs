using System.Runtime.InteropServices;

namespace Ballast.Core.Util;

/// <summary>
/// Decides whether a path the user picked <em>by hand</em> may be deleted.
///
/// <para>
/// <b>Why this is a denylist when <see cref="PathSafety"/> is an allowlist.</b>
/// <see cref="PathSafety"/> guards automated cleaning: the app itself chose those paths, so the
/// only defensible rule is "nothing outside a root we explicitly registered as junk". A denylist
/// there would be reckless — one missing entry and the app silently eats real data with no human
/// in the loop.
/// </para>
///
/// <para>
/// The Disk Space page is the opposite situation. A human browsed their own drive, saw a specific
/// 4 GB file, selected it and confirmed. Running that through <see cref="PathSafety"/> would
/// refuse everything a user actually wants to delete — a video in Downloads is not on any junk
/// allowlist and never will be. Asking the app to decide whether the user's own data is worth
/// keeping is both impossible and not its business.
/// </para>
///
/// <para>
/// So the rule here is narrower on purpose: <b>stop the user destroying the operating system,
/// and nothing more.</b> If a path is not part of Windows, not part of this app, not a folder whose
/// wholesale loss would be catastrophic and unintended, and not a cloud placeholder or a link, it
/// is the user's to delete. Every refusal comes with a plain-language reason the UI can show,
/// because a guard that silently does nothing is worse than one that explains itself.
/// </para>
///
/// <para>
/// Two mitigations carry the risk this leaves: deletions default to the Recycle Bin (see
/// <c>UserFileDeleter</c>), and <see cref="IsRisky"/> lets the UI warn without blocking.
/// </para>
///
/// <para>
/// <b>One rule underpins all of it: a location is judged in exactly one canonical form.</b> Every
/// entry in the tables below is spelled <c>X:\…</c>, so any path expressing the same location in
/// another syntax would match none of them. <c>Path.GetFullPath</c> handles some of that for us —
/// <c>..</c>, doubled separators, 8.3 short names, trailing dots and spaces — but not all of it, so
/// <see cref="Evaluate"/> refuses outright anything that is not a plain local path: UNC and admin
/// shares, <c>\\?\</c> and <c>\\.\</c> device syntax, and alternate data streams. Anything that
/// cannot be reduced to one comparable string is not judged, it is refused.
/// </para>
/// </summary>
public static class SystemPathGuard
{
    private static readonly char[] _separators =
        [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    /// <summary>Characters that cannot appear in an NTFS name, so a path containing one is malformed.</summary>
    private static readonly char[] _reservedNameChars = ['<', '>', '"', '|'];

    private const string RootReason =
        "That is the root of a drive. Pick a file or folder inside it instead.";

    private const string MalformedReason =
        "That path could not be read, so it is being left alone.";

    private const string WildcardReason =
        "Paths with * or ? are not allowed here — pick the exact item to delete.";

    private const string OsReason =
        "This is part of Windows itself. Deleting it would stop your PC from working.";

    private const string ProgramFilesReason =
        "This is where your programs are installed. Remove programs from Settings \u203A Apps instead.";

    private const string NonLocalReason =
        "Only items on a local drive letter can be deleted here. Network shares and Windows " +
        "device paths are not supported.";

    private const string AccountFolderReason =
        "That is a whole user account's folder. Delete individual items inside it instead.";

    private const string AppDataReason =
        "This folder holds the settings and saved data of every program you use. " +
        "Deleting it would reset or break all of them.";

    /// <summary>
    /// Folders refused along with everything inside them.
    /// </summary>
    private static readonly (string Path, string Reason)[] _protectedTrees = BuildProtectedTrees();

    /// <summary>
    /// Folders refused only as an exact match. Their contents stay deletable, which is the whole
    /// point: losing one file out of Documents is an undo away, losing Documents is a catastrophe.
    /// </summary>
    private static readonly (string Path, string Reason)[] _protectedExact = BuildProtectedExact();

    /// <summary>Program Files roots — deleting inside them is allowed but flagged by <see cref="IsRisky"/>.</summary>
    private static readonly string[] _programFilesRoots = BuildProgramFilesRoots();

    /// <summary>Files Windows owns outright, wherever they turn up.</summary>
    private static readonly string[] _protectedFileNames =
        ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "bootnxt", "bootTel.dat"];

    /// <summary>
    /// The folder that holds every account's profile — <c>C:\Users</c> on a default install.
    /// Its direct children are whole accounts, so each one is refused as an exact match even
    /// though only the current user's profile can be resolved by name.
    /// </summary>
    private static readonly string? _accountsRoot = BuildAccountsRoot();

    /// <summary>
    /// Names no user creates. Matched at any depth because a false positive costs nothing and a
    /// false negative means shredding shadow copies or another account's deleted files.
    /// </summary>
    private static readonly string[] _protectedAnywhere =
        ["$Recycle.Bin", "System Volume Information"];

    /// <summary>
    /// Boot data, refused only directly under a drive root. Matching <c>Recovery</c> at any depth
    /// would block an ordinary folder a user happened to name "Recovery" inside Documents.
    /// </summary>
    private static readonly string[] _protectedTopLevel = ["Boot", "EFI", "Recovery"];

    /// <summary>
    /// True when <paramref name="path"/> must not be deleted, with a reason fit to show the user.
    /// Never throws: an unreadable or malformed path is treated as protected.
    /// </summary>
    /// <param name="path">Any path, absolute or relative; resolved before it is judged.</param>
    /// <param name="reason">Plain-language explanation when the result is <c>true</c>; otherwise <c>null</c>.</param>
    public static bool IsProtected(string path, out string? reason)
    {
        try
        {
            return Evaluate(path, out reason);
        }
        catch (Exception)
        {
            // Deliberately catches everything. A guard that throws is a guard the caller might
            // skip, and "we could not tell" has to mean "do not touch it".
            reason = MalformedReason;
            return true;
        }
    }

    /// <summary>
    /// True when the path is safe to delete but the user should be warned first — currently
    /// anything inside Program Files, which is almost always an installed program.
    /// </summary>
    /// <param name="path">Any path, absolute or relative.</param>
    /// <param name="warning">Advice to show alongside the confirmation; <c>null</c> when not risky.</param>
    public static bool IsRisky(string path, out string? warning)
    {
        warning = null;

        try
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            string full = Trim(Path.GetFullPath(path));

            foreach (var root in _programFilesRoots)
            {
                // StartsWith, not Equals: the root itself is refused outright by IsProtected.
                if (full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    warning =
                        "This belongs to an installed program. Uninstalling it from " +
                        "Settings \u203A Apps is safer — deleting the files by hand can leave the " +
                        "program broken but still listed.";
                    return true;
                }
            }

            return false;
        }
        catch (Exception)
        {
            // A path we cannot even parse is IsProtected's problem, not a risk warning.
            return false;
        }
    }

    private static bool Evaluate(string path, out string? reason)
    {
        reason = null;

        if (string.IsNullOrWhiteSpace(path))
        {
            reason = MalformedReason;
            return true;
        }

        foreach (char c in path)
        {
            if (char.IsControl(c))
            {
                reason = MalformedReason;
                return true;
            }
        }

        // Checked before the wildcard rule so a device path gets an accurate reason rather than
        // being refused by accident for containing a '?'. See IsPlainLocalPath for why.
        if (LooksNonLocal(path))
        {
            reason = NonLocalReason;
            return true;
        }

        // SHFileOperation expands wildcards in its source list, so "…\Documents\*" would delete a
        // whole folder while looking like one harmless entry.
        if (path.Contains('*') || path.Contains('?'))
        {
            reason = WildcardReason;
            return true;
        }

        // "C:" resolves to the *current directory* on that drive, so a 2-character string can turn
        // into a deep path. Judge the raw input on length as well as the resolved one.
        if (path.Trim().Length <= 3)
        {
            reason = RootReason;
            return true;
        }

        // GetFullPath collapses "..", expands 8.3 short names such as PROGRA~1, and strips trailing
        // dots and spaces, so no later comparison can be walked around by any of those.
        string full = Path.GetFullPath(path);

        // …but it deliberately leaves \\?\ and \\.\ prefixes alone (no ".." collapsing either) and
        // keeps UNC paths as UNC. Every entry below is a "X:\…" string, so any path naming the same
        // location in another syntax — \\?\C:\Windows, \\.\C:\Windows, \\localhost\C$\Windows —
        // would match none of them and be waved through. Refuse the whole class instead.
        if (!IsPlainLocalPath(full))
        {
            reason = NonLocalReason;
            return true;
        }

        // A colon past the drive letter opens an NTFS alternate data stream, and one stream name is
        // special: "…\Documents::$INDEX_ALLOCATION" *is* the Documents directory, spelled so that
        // none of the exact-match rules below recognise it. The same trick renames the user profile
        // root, the Users folder and every other exact entry. The reserved characters cannot occur
        // in a real NTFS name at all, so a path containing one is malformed by definition.
        if (full.IndexOf(':', 2) >= 0 || full.IndexOfAny(_reservedNameChars, 2) >= 0)
        {
            reason = MalformedReason;
            return true;
        }

        string root = Path.GetPathRoot(full) ?? string.Empty;
        string normalized = Trim(full);

        if (normalized.Length <= 3 ||
            (root.Length > 0 && full.Equals(root, StringComparison.OrdinalIgnoreCase)))
        {
            reason = RootReason;
            return true;
        }

        string relative = normalized.Length > root.Length ? normalized[root.Length..] : string.Empty;
        string[] segments = relative.Split(_separators, StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length == 0)
        {
            reason = RootReason;
            return true;
        }

        foreach (var segment in segments)
        {
            if (_protectedAnywhere.Contains(segment, StringComparer.OrdinalIgnoreCase))
            {
                reason = segment.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase)
                    ? "This is the Recycle Bin's own storage. Use Empty Recycle Bin instead."
                    : "Windows keeps restore points and shadow copies here.";
                return true;
            }
        }

        if (_protectedTopLevel.Contains(segments[0], StringComparer.OrdinalIgnoreCase))
        {
            reason = "This is needed to start Windows.";
            return true;
        }

        if (_protectedFileNames.Contains(segments[^1], StringComparer.OrdinalIgnoreCase))
        {
            reason = "Windows manages this file. Change it in System \u203A Advanced settings if you need to.";
            return true;
        }

        foreach (var (protectedPath, protectedReason) in _protectedTrees)
        {
            if (IsAtOrUnder(normalized, protectedPath))
            {
                reason = protectedReason;
                return true;
            }
        }

        foreach (var (protectedPath, protectedReason) in _protectedExact)
        {
            if (normalized.Equals(protectedPath, StringComparison.OrdinalIgnoreCase))
            {
                reason = protectedReason;
                return true;
            }
        }

        // Only the *current* user's profile can be resolved by name, so every other account folder —
        // C:\Users\Someone, C:\Users\Public, C:\Users\Default — would otherwise be an ordinary
        // deletable folder. Treat any direct child of the accounts root as a profile root.
        if (_accountsRoot is not null &&
            IsDirectChildOf(normalized, _accountsRoot))
        {
            reason = AccountFolderReason;
            return true;
        }

        return IsLinkOrCloudPlaceholder(normalized, ref reason);
    }

    /// <summary>
    /// Refuses links, junctions and cloud placeholders — the target itself <b>and every folder on
    /// the way to it</b>.
    ///
    /// <para>
    /// Checking only the final component is not enough, and the gap is catastrophic. Given a
    /// junction <c>C:\Temp\winlink</c> pointing at <c>C:\Windows</c>, the path
    /// <c>C:\Temp\winlink\System32</c> has no reparse attribute of its own — it resolves straight
    /// through to the real System32 — and matches no protected tree, because every entry in
    /// <see cref="_protectedTrees"/> is spelled <c>C:\Windows\…</c>. So a single junction anyone can
    /// create without administrator rights would hand the deleter a live path to the operating
    /// system. Walking the ancestors closes that, and refusing an item inside a linked folder is a
    /// price worth paying: it is still reachable in its real location.
    /// </para>
    /// </summary>
    private static bool IsLinkOrCloudPlaceholder(string full, ref string? reason)
    {
        string root = Path.GetPathRoot(full) ?? string.Empty;
        string? current = full;
        bool isTarget = true;

        while (current is not null && !current.Equals(root, StringComparison.OrdinalIgnoreCase))
        {
            if (Inspect(current, isTarget, ref reason)) return true;

            isTarget = false;
            current = Path.GetDirectoryName(current);
        }

        return false;
    }

    /// <summary>
    /// Judges one component of a path. A component that does not exist is not a protected location —
    /// a path that is simply gone is the deleter's problem to report.
    /// </summary>
    private static bool Inspect(string path, bool isTarget, ref string? reason)
    {
        if (!File.Exists(path) && !Directory.Exists(path)) return false;

        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (Exception)
        {
            reason = MalformedReason;
            return true;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            reason = isTarget
                ? "This is a link to somewhere else, not a real folder. " +
                  "Delete what it points at instead."
                : $"\u201C{Path.GetFileName(path)}\u201D in this path is a link to somewhere else, " +
                  "so this item is not really here. Delete it in its real location instead.";
            return true;
        }

        if (CloudFiles.IsPlaceholder(attributes))
        {
            reason = isTarget
                ? "This item is stored in the cloud, not on this PC, so deleting it would " +
                  "download it first. Remove it from your cloud folder instead."
                : $"\u201C{Path.GetFileName(path)}\u201D in this path is stored in the cloud, " +
                  "not on this PC. Remove this item from your cloud folder instead.";
            return true;
        }

        return false;
    }

    private static (string Path, string Reason)[] BuildProtectedTrees()
    {
        var list = new List<(string, string)>();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        Add(list, windows, OsReason);
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.System), OsReason);
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), OsReason);

        if (!string.IsNullOrWhiteSpace(windows))
        {
            Add(list, Path.Combine(windows, "System32"), OsReason);
            Add(list, Path.Combine(windows, "SysWOW64"), OsReason);
        }

        // ProgramData is grouped with Windows rather than with Program Files: it holds machine-wide
        // program state (installer caches used for repair and uninstall, security definitions,
        // licence data) that no file browser shows as expendable and that breaks silently.
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "This folder holds settings and installers your programs share. Removing it breaks them.");

        // The app must not delete itself out from under a running operation.
        Add(list, AppContext.BaseDirectory, "That is part of Ballast itself.");

        return Normalize(list);
    }

    private static (string Path, string Reason)[] BuildProtectedExact()
    {
        var list = new List<(string, string)>();

        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), ProgramFilesReason);
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), ProgramFilesReason);

        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Add(list, profile,
            "This is your entire user folder. Delete individual items inside it instead.");

        const string usersReason = "This folder holds every account on this PC.";
        if (!string.IsNullOrWhiteSpace(profile))
            Add(list, Path.GetDirectoryName(profile), usersReason);

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windows))
            Add(list, Path.Combine(Path.GetPathRoot(windows) ?? string.Empty, "Users"), usersReason);

        foreach (var folder in KnownUserFolders())
        {
            string name = Path.GetFileName(Trim(folder));
            Add(list, folder,
                $"\u201C{name}\u201D is one of your main folders. You can delete things inside it, " +
                "but not the folder itself.");
        }

        // AppData is usually the single largest folder under a profile, which makes it the most
        // likely thing a user drilling into a treemap mistakes for junk \u2014 and its wholesale loss
        // takes every program's settings, licences and saved data with it. Individual caches inside
        // it stay deletable, which is what the Junk page is for.
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppDataReason);
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppDataReason);

        if (!string.IsNullOrWhiteSpace(profile))
        {
            Add(list, Path.Combine(profile, "AppData"), AppDataReason);

            foreach (var name in new[] { "Local", "LocalLow", "Roaming" })
                Add(list, Path.Combine(profile, "AppData", name), AppDataReason);
        }

        return Normalize(list);
    }

    private static string? BuildAccountsRoot()
    {
        try
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (string.IsNullOrWhiteSpace(profile)) return null;

            string? parent = Path.GetDirectoryName(Trim(Path.GetFullPath(profile)));

            // A profile sitting directly on a drive root would make every top-level folder on that
            // drive an "account folder"; refuse to derive a rule from it.
            return string.IsNullOrWhiteSpace(parent) || parent.Length <= 3 ? null : Trim(parent);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string[] BuildProgramFilesRoots()
    {
        var list = new List<(string, string)>();
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), string.Empty);
        Add(list, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), string.Empty);
        return [.. Normalize(list).Select(e => e.Path)];
    }

    /// <summary>
    /// The folders whose wholesale loss would be unrecoverable. Both the redirected location
    /// (OneDrive Backup moves Desktop/Documents/Pictures) and the plain profile-relative one are
    /// listed, because redirection usually leaves the original folder on disk too.
    /// </summary>
    private static IEnumerable<string> KnownUserFolders()
    {
        Environment.SpecialFolder[] ids =
        [
            Environment.SpecialFolder.DesktopDirectory,
            Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures,
            Environment.SpecialFolder.MyMusic,
            Environment.SpecialFolder.MyVideos,
        ];

        foreach (var id in ids)
        {
            string resolved = Environment.GetFolderPath(id);
            if (!string.IsNullOrWhiteSpace(resolved)) yield return resolved;
        }

        // Downloads has no SpecialFolder entry, so it needs the known-folder API.
        string? downloads = KnownDownloadsFolder();
        if (!string.IsNullOrWhiteSpace(downloads)) yield return downloads;

        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(profile)) yield break;

        foreach (var name in new[] { "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos" })
            yield return Path.Combine(profile, name);
    }

    private static string? KnownDownloadsFolder()
    {
        // FOLDERID_Downloads
        var id = new Guid("374DE290-123F-4565-9164-39C4925E467B");
        IntPtr buffer = IntPtr.Zero;

        try
        {
            return SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out buffer) == 0
                ? Marshal.PtrToStringUni(buffer)
                : null;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeCoTaskMem(buffer);
        }
    }

    private static void Add(List<(string, string)> list, string? path, string reason)
    {
        if (!string.IsNullOrWhiteSpace(path)) list.Add((path, reason));
    }

    /// <summary>Resolves, de-duplicates and drops anything that came back as a bare drive root.</summary>
    private static (string Path, string Reason)[] Normalize(IEnumerable<(string Path, string Reason)> items)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<(string, string)>();

        foreach (var (path, reason) in items)
        {
            string full;
            try { full = Trim(Path.GetFullPath(path)); }
            catch (Exception) { continue; }

            // A root that resolved to "C:\" would protect the whole drive by accident.
            if (full.Length <= 3) continue;

            if (seen.Add(full)) result.Add((full, reason));
        }

        return [.. result];
    }

    /// <summary>Strips trailing separators while leaving a drive root such as <c>C:\</c> intact.</summary>
    private static string Trim(string full) =>
        full.Length > 3 ? full.TrimEnd(_separators) : full;

    /// <summary>
    /// True when <paramref name="full"/> is an ordinary <c>X:\…</c> path. UNC paths
    /// (<c>\\server\share</c>, including admin shares such as <c>\\localhost\C$</c>) and the
    /// extended and device syntaxes (<c>\\?\</c>, <c>\\.\</c>, <c>\??\</c>, <c>\\?\GLOBALROOT\…</c>,
    /// <c>\\?\Volume{…}\</c>) all name locations this guard has no way to compare against its
    /// tables, and two of them reach the local system folders.
    /// </summary>
    private static bool IsPlainLocalPath(string full) =>
        full.Length >= 3 &&
        char.IsAsciiLetter(full[0]) &&
        full[1] == ':' &&
        (full[2] == Path.DirectorySeparatorChar || full[2] == Path.AltDirectorySeparatorChar);

    /// <summary>Catches non-local syntaxes on the raw input, before normalisation can disguise them.</summary>
    private static bool LooksNonLocal(string path) =>
        path.StartsWith(@"\\", StringComparison.Ordinal) ||
        path.StartsWith("//", StringComparison.Ordinal) ||
        path.StartsWith(@"\??\", StringComparison.Ordinal) ||
        path.StartsWith(@"\\?\", StringComparison.Ordinal);

    private static bool IsDirectChildOf(string candidate, string parent) =>
        IsAtOrUnder(candidate, parent) &&
        !candidate.Equals(parent, StringComparison.OrdinalIgnoreCase) &&
        candidate.IndexOfAny(_separators, parent.Length + 1) < 0;

    private static bool IsAtOrUnder(string candidate, string root) =>
        candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    // DllImport rather than LibraryImport: the source-generated variant needs AllowUnsafeBlocks,
    // which this project does not enable.
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHGetKnownFolderPath(
        ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
}
