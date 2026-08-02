namespace Ballast.Core.Util;

/// <summary>
/// How much a person stands to lose by deleting something, on a five-step ramp.
///
/// <para>
/// <b>Low number means dangerous.</b> The numbers are deliberately fixed and deliberately ordered
/// so the UI can compare them (<c>level &gt;= threshold</c> is "at least this safe") and so a filter
/// slider can run from 1 to 5 without a lookup table. Do not renumber them.
/// </para>
/// </summary>
public enum DeletionRisk
{
    /// <summary>Windows, installed programs' own homes, boot data. The app refuses these outright.</summary>
    System = 1,

    /// <summary>Installed programs, program settings, cloud-synced content. Deleting breaks something.</summary>
    Risky = 2,

    /// <summary>The user's own documents, photos, video and work. Replaceable by nobody.</summary>
    Caution = 3,

    /// <summary>Downloads, build output, logs. Re-downloadable or rebuildable.</summary>
    ProbablySafe = 4,

    /// <summary>Temp files and caches. Windows and apps make new ones on their own.</summary>
    Safe = 5,
}

/// <summary>
/// One item's verdict. <paramref name="Title"/> is a short headline for a list row
/// ("Installed program"); <paramref name="Reason"/> is one plain sentence a non-expert
/// understands, fit to show verbatim in a confirmation dialog.
/// </summary>
public sealed record RiskAssessment(DeletionRisk Level, string Title, string Reason);

/// <summary>
/// Turns a path into a <see cref="DeletionRisk"/> so the Disk Space view can colour it and filter by
/// it. This is <b>advice, not enforcement</b>: <see cref="SystemPathGuard"/> is still the thing that
/// stands between a confirmation dialog and the shell, and <see cref="PathSafety"/> is still the
/// allowlist for automated cleaning. Nothing here may loosen either.
///
/// <para>
/// <b>The two existing guards define the ends of the ramp.</b> Level 1 is exactly
/// <see cref="SystemPathGuard.IsProtected"/> — if the guard refuses a path, this assessor calls it
/// <see cref="DeletionRisk.System"/> and reuses the guard's own sentence, so the two can never tell
/// the user different stories about the same file. Level 5 is exactly
/// <see cref="PathSafety.IsDeletable"/> — the paths the app is already willing to delete unattended.
/// Everything in between is inference, and it errs downwards (towards "risky") on purpose.
/// </para>
///
/// <para>
/// <b>Evaluation order.</b> First match wins, from most to least dangerous:
/// </para>
/// <list type="number">
/// <item><b>System</b> — whatever <see cref="SystemPathGuard"/> refuses: Windows, System32, the
/// Program Files roots, ProgramData, boot and page files, drive roots, profile roots, links,
/// junctions and cloud placeholders.</item>
/// <item><b>Risky</b> — cloud-synced folders, anything inside Program Files, per-user program
/// installs and <c>AppData\Roaming</c>, and executable/driver/installer file names.</item>
/// <item><b>Caution</b> — the user's own work: the personal folders, and document, image, video,
/// audio and source-code file names wherever they sit.</item>
/// <item><b>ProbablySafe</b> — build output, Downloads, cache folders, logs and part-files.</item>
/// <item><b>Safe</b> — everything <see cref="PathSafety"/> already allows.</item>
/// </list>
///
/// <para>
/// Rule 5 is <em>evaluated</em> first even though it ranks last, because two junk roots live inside
/// folders rule 2 would otherwise claim — the Firefox profile caches sit under
/// <c>AppData\Roaming</c>, and <c>%TEMP%</c> sits under <c>AppData\Local</c>. Nothing in rules 2 to 4
/// describes a temp or cache file better than rule 5 does, so hoisting it changes no verdict; it only
/// stops the more general rules stealing paths the app already treats as junk.
/// </para>
///
/// <para>
/// <b>Anything unrecognised is <see cref="DeletionRisk.Caution"/>, not
/// <see cref="DeletionRisk.ProbablySafe"/>.</b> A disk visualiser's whole job is showing people
/// folders they have never seen before. "We do not know what this is" has to read as amber, never as
/// green.
/// </para>
///
/// <para>
/// <b>A folder is never shown as safer than what it holds.</b> Every rule that reads a
/// <em>location</em> is inherited — a folder inside Documents and every file under it are judged by
/// the same rule, so they cannot disagree. The rules that read a <em>file name</em> can: an ordinary
/// looking folder on <c>D:\</c> is level 3 while the <c>.exe</c> inside it is level 2. So when a
/// directory's verdict is 3 or 4 and it exists on disk, the assessor takes <b>one non-recursive
/// listing</b> of it and lowers the folder to the worst level any immediate child's name earns. It
/// never descends, never inspects more than <see cref="MaxChildrenInspected"/> entries, stops the
/// moment it finds a level 2, and skips the listing entirely where file names are not consulted
/// anyway (junk roots and build output). The cost of that bound is real and worth naming: a folder
/// two levels above a program can still read one step safer than the program. The treemap assesses
/// each folder again as the user opens it, so the truth arrives before the delete button does.
/// </para>
/// </summary>
public static class DeletionRiskAssessor
{
    /// <summary>
    /// Ceiling on the non-recursive child listing described above. High enough that an ordinary
    /// folder is read in full, low enough that a cache folder with 200 000 entries in it cannot
    /// stall a treemap that is assessing hundreds of nodes.
    /// </summary>
    private const int MaxChildrenInspected = 256;

    private static readonly char[] _separators =
        [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    /// <summary>Declared first: every builder below reads it.</summary>
    private static readonly string? _userProfile = Resolve(Environment.SpecialFolder.UserProfile);

    /// <summary>The five levels in order, for a filter control that needs to render all of them.</summary>
    public static readonly IReadOnlyList<DeletionRisk> Levels =
    [
        DeletionRisk.System,
        DeletionRisk.Risky,
        DeletionRisk.Caution,
        DeletionRisk.ProbablySafe,
        DeletionRisk.Safe,
    ];

    // ============================================================================ location tables

    /// <summary>
    /// Folder names treated as the user's own, when they sit directly under the profile or directly
    /// under a drive root. Downloads is deliberately absent — it is level 4.
    /// </summary>
    private static readonly HashSet<string> _personalFolderNames =
        new(["Desktop", "Documents", "Pictures", "Music", "Videos"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Sync-client folder names, matched the same way, mapped to the name to show the user.
    /// OneDrive is handled separately because a work account names the folder after the tenant
    /// ("OneDrive - Contoso").
    /// </summary>
    private static readonly Dictionary<string, string> _cloudFolderNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Dropbox"] = "Dropbox",
            ["Google Drive"] = "Google Drive",
            ["GoogleDrive"] = "Google Drive",
            ["My Drive"] = "Google Drive",
            ["iCloudDrive"] = "iCloud Drive",
            ["iCloud Drive"] = "iCloud Drive",
            ["iCloudPhotos"] = "iCloud Photos",
            ["Box"] = "Box",
            ["Box Sync"] = "Box",
            ["Creative Cloud Files"] = "Creative Cloud",
            ["Nextcloud"] = "Nextcloud",
            ["MEGA"] = "MEGA",
            ["pCloudDrive"] = "pCloud",
        };

    /// <summary>The personal folders as the shell actually resolves them, in case they were moved.</summary>
    private static readonly string[] _personalRoots = BuildPersonalRoots();

    /// <summary>Where a program keeps per-user state that is not a cache.</summary>
    private static readonly string[] _settingsRoots = BuildSettingsRoots();

    /// <summary>Per-user program installs — the modern default for Code, Teams, Discord and friends.</summary>
    private static readonly string[] _userProgramRoots = BuildUserProgramRoots();

    private static readonly string[] _downloadRoots = BuildDownloadRoots();

    /// <summary>Sync roots the client told us about through the environment.</summary>
    private static readonly (string Root, string Service)[] _cloudRoots = BuildCloudRoots();

    // =========================================================================== name-based tables

    /// <summary>
    /// Directories whose entire contents a build tool, package manager or runtime will recreate.
    /// Inside one of these, file names are not consulted at all: the compiled executables and the
    /// vendored JavaScript in there are output, not belongings.
    /// </summary>
    private static readonly HashSet<string> _buildOutputNames = new(
    [
        "bin", "obj", "node_modules", "target", ".gradle", "__pycache__", ".venv", "venv",
        ".tox", ".pytest_cache", ".mypy_cache", ".next", ".nuxt", ".turbo", ".parcel-cache",
        ".sass-cache", "CMakeFiles", "cmake-build-debug", "cmake-build-release",
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Directories a program fills with material it can regenerate. Weaker evidence than a junk root,
    /// which is why these land on 4 rather than 5.
    /// </summary>
    private static readonly HashSet<string> _cacheFolderNames = new(
    [
        "Cache", "Caches", "cache2", "GPUCache", "Code Cache", "ShaderCache", "DawnCache",
        "GrShaderCache", "CrashDumps", "Crashpad", "Crash Reports", "Logs", "Temp", "tmp",
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>Programs are made of these. Losing one usually breaks whatever owns it.</summary>
    private static readonly HashSet<string> _executableExtensions = new(
    [
        ".exe", ".dll", ".sys", ".driver", ".drv", ".ocx", ".cpl", ".com", ".efi", ".ax",
        ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".msp", ".msu",
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Work nobody else has a copy of. Source code is in here for the same reason a photo is: it is
    /// the user's own, and a treemap that painted a source tree green would be lying.
    /// </summary>
    private static readonly HashSet<string> _personalExtensions = new(
    [
        // Documents
        ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
        ".pdf", ".rtf", ".txt", ".md", ".csv", ".odt", ".ods", ".odp", ".pages", ".numbers",
        ".key", ".epub", ".one", ".pst", ".ost", ".kdbx",
        // Design
        ".psd", ".psb", ".ai", ".indd", ".xcf", ".sketch", ".fig", ".afphoto", ".afdesign",
        ".cdr", ".svg", ".blend", ".skp", ".dwg", ".dxf",
        // Photos
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".webp",
        ".raw", ".cr2", ".cr3", ".nef", ".arw", ".dng", ".orf", ".rw2", ".raf", ".srw",
        // Video
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".m4v", ".mpg", ".mpeg", ".3gp", ".webm",
        ".mts", ".m2ts", ".flv",
        // Audio
        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".oga", ".wma", ".aiff", ".aif",
        // Source
        ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".kt", ".swift", ".go", ".rs",
        ".py", ".rb", ".php", ".js", ".jsx", ".ts", ".tsx", ".sql", ".xaml", ".vue", ".r",
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>Written to be thrown away, wherever they ended up.</summary>
    private static readonly HashSet<string> _disposableExtensions = new(
    [
        ".log", ".log1", ".log2", ".etl", ".evtx", ".dmp", ".mdmp", ".hdmp",
        ".tmp", ".temp", ".crdownload", ".part", ".partial", ".download",
    ], StringComparer.OrdinalIgnoreCase);

    // ==================================================================================== the API

    /// <summary>
    /// Rates <paramref name="path"/>. Never throws: a path that cannot be read comes back as
    /// <see cref="DeletionRisk.System"/>, because "we could not tell" has to mean "leave it alone".
    /// </summary>
    /// <param name="path">Any path, absolute or relative; resolved before it is judged.</param>
    /// <param name="isDirectory">
    /// True for a folder. Callers must get this right: it decides whether the trailing part of the
    /// name is read as a file extension, and whether the folder's own contents are consulted.
    /// </param>
    public static RiskAssessment Assess(string path, bool isDirectory)
    {
        try
        {
            return Evaluate(path, isDirectory);
        }
        catch (Exception)
        {
            return new RiskAssessment(
                DeletionRisk.System,
                "Never delete",
                "This item could not be read, so it is being left alone.");
        }
    }

    /// <summary>One sentence describing a whole level, for the filter control's own labelling.</summary>
    public static string Describe(DeletionRisk level) => level switch
    {
        DeletionRisk.System =>
            "Windows itself and the files it starts from. Deleting these stops your PC working.",
        DeletionRisk.Risky =>
            "Installed programs, their settings, and anything synced to the cloud. Deleting these breaks something.",
        DeletionRisk.Caution =>
            "Your own documents, photos, video and work. Nothing else has a copy of these.",
        DeletionRisk.ProbablySafe =>
            "Downloads, build output and old logs. You can download or rebuild these again.",
        DeletionRisk.Safe =>
            "Temporary files and caches. Windows and your apps make new ones whenever they need them.",
        _ => string.Empty,
    };

    /// <summary>Two or three words for a chip, a legend or a slider tick.</summary>
    public static string ShortLabel(DeletionRisk level) => level switch
    {
        DeletionRisk.System => "System",
        DeletionRisk.Risky => "Risky",
        DeletionRisk.Caution => "Caution",
        DeletionRisk.ProbablySafe => "Probably safe",
        DeletionRisk.Safe => "Safe",
        _ => string.Empty,
    };

    /// <summary>
    /// True when <paramref name="level"/> carries <b>no more risk</b> than <paramref name="threshold"/>,
    /// which is what a filter reading "show me everything at least this safe" needs.
    ///
    /// <para>
    /// The comparison looks inverted and is not: the numbers run from 1 (most dangerous) to 5
    /// (safest), so "at or below this much risk" is "at or above this number". This method exists
    /// precisely so no call site has to remember that.
    /// </para>
    /// </summary>
    public static bool IsAtOrBelow(DeletionRisk level, DeletionRisk threshold) => level >= threshold;

    // ================================================================================ the ordering

    private static RiskAssessment Evaluate(string path, bool isDirectory)
    {
        // ---- 1. System. The guard has the last word, and its wording is already user-facing, so
        // reuse it rather than inventing a second explanation for the same refusal.
        if (SystemPathGuard.IsProtected(path, out string? guardReason))
        {
            return new RiskAssessment(
                DeletionRisk.System,
                "Never delete",
                string.IsNullOrWhiteSpace(guardReason)
                    ? "Windows needs this, so it is being left alone."
                    : guardReason);
        }

        string full = Trim(Path.GetFullPath(path));
        string[] segments = Segments(full);
        string extension = isDirectory ? string.Empty : Path.GetExtension(full);

        // ---- 5, hoisted. See the class remarks: this changes no verdict, it only stops the broader
        // rules below claiming paths the app already cleans unattended.
        if (PathSafety.IsDeletable(full))
        {
            return new RiskAssessment(
                DeletionRisk.Safe,
                isDirectory ? "Temporary files" : "Temporary file",
                "This is a temporary or cached copy. Windows and your apps make new ones when they need them.");
        }

        string top = TopLevelName(full, segments);
        bool inBuildOutput = HasSegment(segments, _buildOutputNames);
        bool inDownloads = IsUnder(full, _downloadRoots) ||
                           top.Equals("Downloads", StringComparison.OrdinalIgnoreCase);

        // ---- 2. Risky.
        if (CloudService(full, top) is { } service)
        {
            return new RiskAssessment(
                DeletionRisk.Risky,
                $"Synced with {service}",
                $"This is kept in sync with {service}, so deleting it here also removes it from the " +
                "cloud and from your other devices.");
        }

        if (SystemPathGuard.IsRisky(full, out string? programWarning))
        {
            return new RiskAssessment(
                DeletionRisk.Risky,
                "Installed program",
                string.IsNullOrWhiteSpace(programWarning)
                    ? "This belongs to a program you installed. Uninstall it from Settings \u203A Apps instead."
                    : programWarning);
        }

        if (IsUnder(full, _userProgramRoots))
        {
            return new RiskAssessment(
                DeletionRisk.Risky,
                "Installed program",
                "A program you installed lives here. Uninstall it from Settings \u203A Apps instead of " +
                "deleting its files.");
        }

        if (IsUnder(full, _settingsRoots))
        {
            return new RiskAssessment(
                DeletionRisk.Risky,
                "Program settings",
                "A program keeps its settings, sign-ins and licence here, so deleting this can log you " +
                "out or reset it.");
        }

        // Build output and Downloads are the two places these names mean something else: your own
        // compiler wrote the first, and an installer you already ran is the second.
        if (!inBuildOutput && !inDownloads && _executableExtensions.Contains(extension))
        {
            return new RiskAssessment(
                DeletionRisk.Risky,
                "Program file",
                "Programs are built out of files like this one. Deleting it usually stops something working.");
        }

        // ---- 3 and 4, plus the unrecognised default.
        RiskAssessment verdict = Classify(full, top, extension, segments, isDirectory, inBuildOutput, inDownloads);

        // ---- the folder floor. Files answer for themselves.
        return isDirectory && !inBuildOutput
            ? LowerToWorstChild(full, verdict, inDownloads)
            : verdict;
    }

    private static RiskAssessment Classify(
        string full,
        string top,
        string extension,
        string[] segments,
        bool isDirectory,
        bool inBuildOutput,
        bool inDownloads)
    {
        // ---- 3. Caution. Skipped inside build output, where a .png is an icon shipped with a
        // package rather than a photograph — and where letting one file drop to 3 would make the
        // folder above it read as safer than its own contents.
        if (!inBuildOutput)
        {
            if (_personalExtensions.Contains(extension))
            {
                return new RiskAssessment(
                    DeletionRisk.Caution,
                    "Your own file",
                    "This looks like something you made or saved yourself, and nothing else has a copy of it.");
            }

            if (IsUnder(full, _personalRoots) || _personalFolderNames.Contains(top))
            {
                return new RiskAssessment(
                    DeletionRisk.Caution,
                    "In your personal folders",
                    "This sits among your own documents and photos, so it may be something you want to keep.");
            }
        }

        // ---- 4. ProbablySafe.
        if (inBuildOutput)
        {
            return new RiskAssessment(
                DeletionRisk.ProbablySafe,
                "Build output",
                "A build or a package manager put this here, and running the build again would make it once more.");
        }

        if (inDownloads)
        {
            return new RiskAssessment(
                DeletionRisk.ProbablySafe,
                isDirectory ? "Downloaded files" : "Downloaded file",
                "This came from the internet, so you can download it again if you find you still need it.");
        }

        if (_disposableExtensions.Contains(extension))
        {
            return new RiskAssessment(
                DeletionRisk.ProbablySafe,
                "Log or leftover file",
                "This is a log or a half-finished file a program left behind, not something you saved.");
        }

        if (HasSegment(segments, _cacheFolderNames))
        {
            return new RiskAssessment(
                DeletionRisk.ProbablySafe,
                "Cache",
                "A program keeps a spare copy of things here to load them faster, and will rebuild it if it goes.");
        }

        // ---- the default. Amber, never green: see the class remarks.
        return new RiskAssessment(
            DeletionRisk.Caution,
            isDirectory ? "Unrecognised folder" : "Unrecognised file",
            "Nothing about this says what it is, so it is being treated as something you may want to keep.");
    }

    /// <summary>
    /// Drops a folder's verdict to the worst level any of its immediate children's names earns, so a
    /// folder can never be painted safer than what is visibly inside it. Bounded and non-recursive —
    /// see the class remarks for what that bound costs.
    /// </summary>
    private static RiskAssessment LowerToWorstChild(string full, RiskAssessment verdict, bool inDownloads)
    {
        if (verdict.Level is not (DeletionRisk.Caution or DeletionRisk.ProbablySafe)) return verdict;

        DeletionRisk worst = verdict.Level;
        string? culprit = null;

        try
        {
            if (!Directory.Exists(full)) return verdict;

            int inspected = 0;

            // ShallowEnumeration tolerates inaccessible entries, never recurses, and skips links and
            // cloud placeholders — so this cannot escape the folder or trigger a download.
            foreach (string child in Directory.EnumerateFiles(full, "*", CloudFiles.ShallowEnumeration()))
            {
                if (++inspected > MaxChildrenInspected) break;

                if (NameLevel(Path.GetExtension(child), inDownloads) is not { } level) continue;
                if (level >= worst) continue;

                worst = level;
                culprit = Path.GetFileName(child);

                if (worst == DeletionRisk.Risky) break; // nothing a name can say is worse
            }
        }
        catch (Exception)
        {
            // A folder we could not list tells us nothing new; keep the verdict we already have.
            return verdict;
        }

        if (worst == verdict.Level || culprit is null) return verdict;

        return worst == DeletionRisk.Risky
            ? new RiskAssessment(
                DeletionRisk.Risky,
                "Holds program files",
                $"This folder holds program files such as \u201C{culprit}\u201D, so deleting it would " +
                "stop something working.")
            : new RiskAssessment(
                DeletionRisk.Caution,
                "Holds your own files",
                $"This folder holds files of your own such as \u201C{culprit}\u201D, which nothing else " +
                "has a copy of.");
    }

    /// <summary>The level a file name alone implies, or null when the name says nothing.</summary>
    private static DeletionRisk? NameLevel(string extension, bool inDownloads)
    {
        if (!inDownloads && _executableExtensions.Contains(extension)) return DeletionRisk.Risky;
        if (_personalExtensions.Contains(extension)) return DeletionRisk.Caution;
        return null;
    }

    // ================================================================================== locations

    /// <summary>
    /// The sync service this path belongs to, or null. Checks the roots the sync clients publish
    /// through the environment first, then the folder name — <c>OneDrive - Contoso</c> for a work
    /// account, and the fixed names every other client uses.
    /// </summary>
    private static string? CloudService(string full, string top)
    {
        foreach (var (root, service) in _cloudRoots)
        {
            if (IsAtOrUnder(full, root)) return service;
        }

        if (top.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase)) return "OneDrive";

        return _cloudFolderNames.TryGetValue(top, out string? named) ? named : null;
    }

    /// <summary>
    /// The name that says what part of the disk this is: the segment under the user profile when the
    /// path is inside it, and the segment under the drive root otherwise. That one rule covers both
    /// <c>C:\Users\me\Documents\…</c> and the very common <c>D:\Documents\…</c> without a table of
    /// every drive.
    /// </summary>
    private static string TopLevelName(string full, string[] segments)
    {
        if (_userProfile is not null && FirstSegmentUnder(full, _userProfile) is { } underProfile)
            return underProfile;

        return segments.Length > 0 ? segments[0] : string.Empty;
    }

    private static string[] BuildPersonalRoots()
    {
        var list = new List<string?>
        {
            Resolve(Environment.SpecialFolder.DesktopDirectory),
            Resolve(Environment.SpecialFolder.MyDocuments),
            Resolve(Environment.SpecialFolder.MyPictures),
            Resolve(Environment.SpecialFolder.MyMusic),
            Resolve(Environment.SpecialFolder.MyVideos),
        };

        if (_userProfile is not null)
        {
            foreach (string name in _personalFolderNames) list.Add(Combine(_userProfile, name));
        }

        return Clean(list);
    }

    private static string[] BuildSettingsRoots()
    {
        var list = new List<string?> { Resolve(Environment.SpecialFolder.ApplicationData) };

        if (_userProfile is not null)
            list.Add(Combine(_userProfile, Path.Combine("AppData", "Roaming")));

        return Clean(list);
    }

    private static string[] BuildUserProgramRoots()
    {
        var list = new List<string?>();

        if (Resolve(Environment.SpecialFolder.LocalApplicationData) is { } local)
            list.Add(Combine(local, "Programs"));

        if (_userProfile is not null)
            list.Add(Combine(_userProfile, Path.Combine("AppData", "Local", "Programs")));

        return Clean(list);
    }

    /// <summary>
    /// Downloads has no <see cref="Environment.SpecialFolder"/> entry, and this file may not reach
    /// into <see cref="SystemPathGuard"/>'s known-folder lookup, so it is matched by name: under the
    /// profile, or directly under a drive root, which is where a moved Downloads folder almost always
    /// ends up. A Downloads redirected into OneDrive is caught one rule earlier as synced content.
    /// </summary>
    private static string[] BuildDownloadRoots()
    {
        var list = new List<string?>();

        if (_userProfile is not null) list.Add(Combine(_userProfile, "Downloads"));

        return Clean(list);
    }

    private static (string Root, string Service)[] BuildCloudRoots()
    {
        var list = new List<(string Root, string Service)>();

        foreach (string variable in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
        {
            if (Normalize(SafeEnvironmentVariable(variable)) is { Length: > 3 } root)
                list.Add((root, "OneDrive"));
        }

        if (_userProfile is not null)
        {
            foreach (var (name, service) in _cloudFolderNames)
            {
                if (Combine(_userProfile, name) is { } root && root.Length > 3)
                    list.Add((root, service));
            }
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return [.. list.Where(entry => seen.Add(entry.Root))];
    }

    // ==================================================================================== plumbing

    private static string? SafeEnvironmentVariable(string name)
    {
        try { return Environment.GetEnvironmentVariable(name); }
        catch (Exception) { return null; }
    }

    private static string? Resolve(Environment.SpecialFolder id)
    {
        try { return Normalize(Environment.GetFolderPath(id)); }
        catch (Exception) { return null; }
    }

    private static string? Combine(string root, string name)
    {
        try { return Normalize(Path.Combine(root, name)); }
        catch (Exception) { return null; }
    }

    private static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;

        try { return Trim(Path.GetFullPath(path)); }
        catch (Exception) { return null; }
    }

    /// <summary>Drops blanks, duplicates and anything that collapsed to a bare drive root.</summary>
    private static string[] Clean(IEnumerable<string?> values) =>
    [
        .. values
            .Where(value => value is { Length: > 3 })
            .Select(value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
    ];

    private static bool IsUnder(string full, string[] roots)
    {
        foreach (string root in roots)
        {
            if (IsAtOrUnder(full, root)) return true;
        }

        return false;
    }

    private static bool IsAtOrUnder(string candidate, string root) =>
        root.Length > 0 &&
        (candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
         candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

    private static string? FirstSegmentUnder(string full, string root)
    {
        if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return null;

        string rest = full[(root.Length + 1)..];
        int cut = rest.IndexOfAny(_separators);
        return cut < 0 ? rest : rest[..cut];
    }

    private static bool HasSegment(string[] segments, HashSet<string> names)
    {
        foreach (string segment in segments)
        {
            if (names.Contains(segment)) return true;
        }

        return false;
    }

    private static string[] Segments(string full)
    {
        string root = Path.GetPathRoot(full) ?? string.Empty;
        string relative = full.Length > root.Length ? full[root.Length..] : string.Empty;
        return relative.Split(_separators, StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>Strips trailing separators while leaving a drive root such as <c>C:\</c> intact.</summary>
    private static string Trim(string full) =>
        full.Length > 3 ? full.TrimEnd(_separators) : full;
}
