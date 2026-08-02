namespace Ballast.Core.Models;

/// <summary>
/// One thing that can be deleted. Produced by scanners; never deleted at scan time.
/// </summary>
public sealed class CleanupItem
{
    public required string Path { get; init; }
    public required JunkCategory Category { get; init; }
    public long SizeBytes { get; init; }

    /// <summary>True when <see cref="Path"/> is a directory that should be removed wholesale.</summary>
    public bool IsDirectory { get; init; }

    /// <summary>True when deleting this needs an elevated process.</summary>
    public bool RequiresAdmin { get; init; }

    /// <summary>Human-friendly label; falls back to the file name.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// Special-cased items (the Recycle Bin) are emptied through a shell API rather than
    /// a file delete. <see cref="Path"/> is not a real path in that case.
    /// </summary>
    public bool IsVirtual { get; init; }

    public string DisplayName =>
        Description ?? (System.IO.Path.GetFileName(Path) is { Length: > 0 } n ? n : Path);
}
