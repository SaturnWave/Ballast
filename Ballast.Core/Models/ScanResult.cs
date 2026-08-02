namespace Ballast.Core.Models;

/// <summary>Outcome of one scanner run.</summary>
public sealed class ScanResult
{
    public IReadOnlyList<CleanupItem> Items { get; init; } = [];

    /// <summary>Paths the scanner could not read (access denied, locked). Informational, not fatal.</summary>
    public IReadOnlyList<string> SkippedPaths { get; init; } = [];

    public long TotalBytes => Items.Sum(i => i.SizeBytes);
    public int Count => Items.Count;

    public static ScanResult Empty { get; } = new();
}
