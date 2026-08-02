using Ballast.Core.Util;

namespace Ballast.Core.DiskAnalysis;

/// <summary>
/// One node of a scanned directory tree: either a folder or a file.
///
/// <para>
/// <see cref="SizeBytes"/> and <see cref="FileCount"/> are aggregates that include every
/// descendant, and they are written while the tree is being built (see
/// <see cref="DirectoryTreeScanner"/>). Treat a node as read-only once the scan that produced
/// it has completed.
/// </para>
///
/// <para>This type is purely descriptive — nothing here deletes anything.</para>
/// </summary>
public sealed class DirNode
{
    /// <summary>Leaf name of the entry ("Downloads", "setup.exe"), or the full path for a drive root.</summary>
    public required string Name { get; init; }

    /// <summary>Absolute path of the entry.</summary>
    public required string FullPath { get; init; }

    /// <summary>
    /// Total bytes of this node <em>including</em> all descendants. Mutable because the scanner
    /// aggregates bottom-up as it unwinds the walk; stable once the scan finishes.
    /// </summary>
    public long SizeBytes { get; set; }

    /// <summary>
    /// Number of files at or below this node. Files count 1; folders count the sum of their
    /// subtree. Files skipped by <see cref="TreeScanOptions.MinimumFileSizeBytes"/> are still
    /// counted here even though they get no node of their own.
    /// </summary>
    public long FileCount { get; set; }

    /// <summary>True for folders, false for files.</summary>
    public bool IsDirectory { get; init; }

    /// <summary>Back-reference to the containing folder; <see langword="null"/> for the scan root.</summary>
    public DirNode? Parent { get; init; }

    /// <summary>
    /// Direct children, in filesystem enumeration order (not sorted). Populated only for folders.
    /// </summary>
    public List<DirNode> Children { get; } = [];

    /// <summary>True when this node has at least one child node.</summary>
    public bool HasChildren => Children.Count > 0;

    /// <summary>Pre-formatted size for direct UI binding.</summary>
    public string SizeDisplay => ByteFormatter.Format(SizeBytes);

    /// <summary>
    /// The <paramref name="count"/> biggest children, largest first. Never throws for a
    /// non-positive <paramref name="count"/> — it simply yields nothing.
    /// </summary>
    public IEnumerable<DirNode> TopChildren(int count) =>
        Children.OrderByDescending(c => c.SizeBytes).Take(Math.Max(0, count));

    /// <summary>
    /// This node's share of its parent, in the range 0..1. Returns 0 for the root and whenever
    /// the parent measured as empty, so callers can multiply by it without guarding.
    /// </summary>
    public double FractionOfParent =>
        Parent is { SizeBytes: > 0 } parent ? (double)SizeBytes / parent.SizeBytes : 0d;

    public override string ToString() => $"{Name} ({SizeDisplay})";
}
