using System.Runtime.InteropServices;
using Ballast.Core.Models;
using Ballast.Core.Util;

namespace Ballast.Core.Cleaning;

/// <summary>
/// Deletes files and folders the user picked by hand on the Disk Space page.
///
/// <para>
/// <b>The Recycle Bin is the default, and that is the most important decision in this file.</b>
/// <see cref="CleaningService"/> deletes caches — regenerable by definition, so a hard delete is
/// fine. This class deletes holiday photos, project folders and tax returns. The user is one
/// mis-click away from losing something irreplaceable, and no confirmation dialog reliably prevents
/// that. So the normal path routes everything through the shell with <c>FOF_ALLOWUNDO</c>: the item
/// lands in the Recycle Bin, the disk-space figure the user came for still improves once they empty
/// it, and a mistake costs a restore rather than a recovery service.
/// </para>
///
/// <para>
/// <paramref name="permanent"/> exists because the Recycle Bin genuinely cannot take everything —
/// items larger than the bin's quota, and volumes with no bin at all. When a recycle attempt fails
/// for one of those reasons this class <b>reports it and stops</b>. It never quietly upgrades to a
/// permanent delete, because "I clicked Delete and it went to the Recycle Bin, except that one
/// time" is exactly how irreplaceable data disappears.
/// </para>
///
/// <para>
/// Every path is re-checked through <see cref="SystemPathGuard"/> immediately before the shell call.
/// The caller's list is untrusted input: a stale tree node, a path edited in the UI, or a bug
/// upstream must not be able to reach <c>SHFileOperation</c> unexamined.
/// </para>
/// </summary>
public sealed class UserFileDeleter
{
    /// <summary>Shared instance; this type holds no state.</summary>
    public static UserFileDeleter Shared { get; } = new();

    private static readonly char[] _separators =
        [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];

    /// <summary>
    /// Reason suffix on failures the user can resolve by choosing a permanent delete. The UI can
    /// look for it to offer that follow-up instead of leaving a dead end.
    /// </summary>
    public const string PermanentDeleteHint = "Delete it permanently to remove it.";

    /// <summary>
    /// Deletes each path, reporting per-path failures rather than aborting the batch.
    /// </summary>
    /// <param name="paths">Paths chosen by the user. Treated as untrusted.</param>
    /// <param name="permanent">
    /// <c>false</c> (default) sends items to the Recycle Bin. <c>true</c> bypasses it — only for an
    /// explicit, separately confirmed user choice.
    /// </param>
    /// <param name="progress">Optional per-item progress.</param>
    /// <param name="ct">Cancellation checked between items; a single shell call is not interruptible.</param>
    public Task<CleanReport> DeleteAsync(
        IEnumerable<string> paths,
        bool permanent = false,
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default)
        => Task.Run(() => Delete(Prepare(paths), permanent, progress, ct), ct);

    private static CleanReport Delete(
        List<string> targets,
        bool permanent,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        long freed = 0;
        int deleted = 0;
        var failures = new List<CleanFailure>();

        // Folders successfully removed in this batch. Anything inside one of these is already gone
        // and its bytes are already counted in the folder's measurement.
        var removed = new List<string>();

        ActionLog.Info(
            $"User delete started: {targets.Count} item(s), " +
            (permanent ? "PERMANENT (bypassing Recycle Bin)" : "to Recycle Bin") +
            (Elevation.IsElevated ? " [elevated]" : " [standard user]"));

        for (int i = 0; i < targets.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            string target = targets[i];

            void Fail(string reason)
            {
                failures.Add(new CleanFailure(target, reason));
                ActionLog.Failed(target, reason);
            }

            try
            {
                if (WasRemovedWithParent(removed, target))
                {
                    ActionLog.Info($"Skipped (already removed with its parent folder): {target}");
                }
                // Re-validated here, immediately before the shell call — never earlier and cached.
                else if (SystemPathGuard.IsProtected(target, out var reason))
                {
                    Fail(reason ?? "This location is protected.");
                }
                else if (!File.Exists(target) && !Directory.Exists(target))
                {
                    Fail("This item no longer exists.");
                }
                else if (!permanent && !VolumeHasRecycleBin(target))
                {
                    // Caught before the call, not after: with FOF_NOCONFIRMATION the shell would
                    // suppress its own "permanently delete?" prompt and destroy the item outright.
                    Fail($"This drive has no Recycle Bin. {PermanentDeleteHint}");
                }
                else
                {
                    bool wasFolder = Directory.Exists(target);

                    // Measured first — once the item is in the bin its size is no longer readable.
                    long size = MeasureSize(target, ct);

                    string? failure = ShellDelete(target, permanent);
                    if (failure is not null)
                    {
                        Fail(failure);
                    }
                    else
                    {
                        freed += size;
                        deleted++;
                        if (wasFolder) removed.Add(target);
                        ActionLog.Deleted(target, size);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Fail(ex.Message);
            }

            progress?.Report(new ScanProgress(
                target, deleted, freed,
                Fraction: targets.Count == 0 ? 1 : (double)(i + 1) / targets.Count));
        }

        ActionLog.Info(
            $"User delete finished: {ByteFormatter.Format(freed)} freed, " +
            $"{deleted} item(s) removed, {failures.Count} failure(s)");

        return new CleanReport
        {
            BytesFreed = freed,
            ItemsDeleted = deleted,
            Failures = failures,
        };
    }

    /// <summary>
    /// Resolves and de-duplicates the request, then orders it so that a containing folder is always
    /// processed before anything inside it.
    ///
    /// <para>
    /// The ordering is what lets the loop skip an item whose parent folder has <em>already been
    /// deleted</em> — the honest version of "this was covered by another entry". Discarding nested
    /// entries up front instead would be a silent-data-loss bug: if the parent is then refused by
    /// the guard or fails to delete, the child would never be attempted and never appear in
    /// <see cref="CleanReport.Failures"/>, so the user would be told their file was handled when
    /// it was not.
    /// </para>
    ///
    /// <para>An ancestor is always a strictly shorter string than its descendants, so ordering by
    /// length is enough to guarantee parents come first.</para>
    /// </summary>
    private static List<string> Prepare(IEnumerable<string> paths)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var resolved = new List<string>();

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;

            string full;
            try
            {
                full = Path.GetFullPath(raw);
                if (full.Length > 3) full = full.TrimEnd(_separators);
            }
            catch (Exception)
            {
                full = raw; // left as-is; SystemPathGuard will reject it with a reason
            }

            if (seen.Add(full)) resolved.Add(full);
        }

        return [.. resolved.OrderBy(p => p.Length)];
    }

    /// <summary>
    /// True when a folder deleted earlier in this batch already contained <paramref name="path"/>.
    /// Only folders this run actually removed are consulted, so a refused or failed parent still
    /// leaves its children to be attempted and reported on their own.
    /// </summary>
    private static bool WasRemovedWithParent(List<string> removed, string path) =>
        removed.Any(parent =>
            path.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

    private static long MeasureSize(string path, CancellationToken ct)
    {
        try
        {
            if (Directory.Exists(path)) return FileSystemProbe.DirectorySize(path, null, ct);
            if (File.Exists(path)) return new FileInfo(path).Length;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Deliberately broad, cancellation aside. Anything narrower and a measurement failure
            // escapes to the caller's catch, where it is reported as "this item could not be
            // deleted" — telling the user their delete failed because the *sizing* failed, and
            // leaving the item on disk. An unmeasurable item still deletes; it just contributes 0
            // to the honest total.
        }

        return 0;
    }

    /// <summary>
    /// Best-effort check that the item's volume actually has a Recycle Bin. Network shares and some
    /// removable volumes have none, and the shell would permanently delete instead.
    /// </summary>
    private static bool VolumeHasRecycleBin(string path)
    {
        try
        {
            string? root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root)) return false;

            var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf<SHQUERYRBINFO>() };
            return SHQueryRecycleBin(root, ref info) == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false; // cannot verify: refuse to recycle rather than risk a hard delete
        }
    }

    /// <summary>Returns <c>null</c> on success, otherwise a user-facing failure reason.</summary>
    private static string? ShellDelete(string path, bool permanent)
    {
        ushort flags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMMKDIR;

        // FOF_WANTNUKEWARNING is the only thing standing between "we promised the Recycle Bin" and a
        // silent permanent delete. FOF_ALLOWUNDO is a *request*: the shell falls back to destroying
        // the item when the bin cannot take it — over quota, or recycling switched off for that
        // volume by policy (NukeOnDelete), which SHQueryRecycleBin reports as a perfectly healthy
        // bin. FOF_NOCONFIRMATION would then suppress the shell's own "permanently delete?" prompt
        // and the item would be gone with nothing but a success code to show for it.
        // FOF_WANTNUKEWARNING partially overrides FOF_NOCONFIRMATION for exactly that case: the user
        // is asked, and a refusal comes back as DE_OPCANCELLED, which Describe reports.
        if (!permanent) flags |= (ushort)(FOF_ALLOWUNDO | FOF_WANTNUKEWARNING);

        var operation = new SHFILEOPSTRUCT
        {
            hwnd = IntPtr.Zero,
            wFunc = FO_DELETE,
            // pFrom is a *double*-null-terminated list, not a plain string: each path ends with
            // '\0' and an extra '\0' closes the list. The LPWStr marshaller supplies exactly one
            // trailing '\0', so the terminator appended here becomes the second one. Omitting it is
            // the classic SHFileOperation bug — the shell then reads past the buffer and either
            // fails with a nonsense code or picks up whatever memory follows as another path.
            pFrom = path + '\0',
            pTo = null,
            fFlags = flags,
            fAnyOperationsAborted = false,
            hNameMappings = IntPtr.Zero,
            lpszProgressTitle = null,
        };

        int result;
        try
        {
            result = SHFileOperationW(ref operation);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return "The Windows shell could not be reached to delete this item.";
        }

        if (result == 0)
        {
            return operation.fAnyOperationsAborted
                ? "Windows stopped before deleting this item."
                : null;
        }

        return Describe(result, permanent);
    }

    private static string Describe(int code, bool permanent) => code switch
    {
        // The item was too big for the bin. Reported, never silently hard-deleted.
        DE_FILE_TOO_LARGE when !permanent => $"Too large for the Recycle Bin. {PermanentDeleteHint}",
        DE_FILE_TOO_LARGE => "Too large for the destination.",

        DE_ACCESSDENIEDSRC or ERROR_ACCESS_DENIED =>
            "Access denied. It may need administrator rights.",
        ERROR_SHARING_VIOLATION => "In use by another program.",
        ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND => "This item no longer exists.",
        DE_PATHTOODEEP or DE_FILENAMETOOLONG => "The path is too long for Windows to delete.",
        DE_INVALIDFILES => "Windows did not recognise this path.",
        DE_OPCANCELLED => "The delete was cancelled.",
        DE_ROOTDIR => "Windows refused: that is a drive root.",
        DE_UNKNOWN => "Windows could not delete this item and did not say why.",
        _ => $"Windows reported error 0x{code:X} while deleting this item.",
    };

    // ---- Win32 ----------------------------------------------------------------------------

    private const uint FO_DELETE = 0x0003;

    private const ushort FOF_SILENT = 0x0004;         // no progress dialog
    private const ushort FOF_NOCONFIRMATION = 0x0010; // no "are you sure"
    private const ushort FOF_ALLOWUNDO = 0x0040;      // the whole point: recycle instead of destroy
    private const ushort FOF_NOCONFIRMMKDIR = 0x0200;
    private const ushort FOF_NOERRORUI = 0x0400;      // report errors to us, not in a message box
    private const ushort FOF_WANTNUKEWARNING = 0x4000; // ask before destroying instead of recycling

    // SHFileOperation predates HRESULTs and returns its own DE_* codes alongside Win32 ones.
    private const int ERROR_FILE_NOT_FOUND = 0x02;
    private const int ERROR_PATH_NOT_FOUND = 0x03;
    private const int ERROR_ACCESS_DENIED = 0x05;
    private const int ERROR_SHARING_VIOLATION = 0x20;
    private const int DE_ROOTDIR = 0x74;
    private const int DE_OPCANCELLED = 0x75;
    private const int DE_ACCESSDENIEDSRC = 0x78;
    private const int DE_PATHTOODEEP = 0x79;
    private const int DE_INVALIDFILES = 0x7C;
    private const int DE_FILENAMETOOLONG = 0x81;
    private const int DE_FILE_TOO_LARGE = 0x85;
    private const int DE_UNKNOWN = 0x402;

    /// <remarks>
    /// Natural (unpacked) alignment matches the Win32 header: on x64 <c>wFunc</c> is followed by
    /// 4 bytes of padding before <c>pFrom</c>, and the WORD <c>fFlags</c> by 2 before the BOOL.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        public string pFrom;
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public string? lpszProgressTitle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO
    {
        public int cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    // DllImport rather than LibraryImport: the source-generated variant needs AllowUnsafeBlocks,
    // which this project does not enable.
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperationW(ref SHFILEOPSTRUCT lpFileOp);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);
}
