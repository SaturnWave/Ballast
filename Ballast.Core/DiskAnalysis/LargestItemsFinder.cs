namespace Ballast.Core.DiskAnalysis;

/// <summary>
/// Pulls the top-N biggest files or folders out of a completed <see cref="DirNode"/> tree.
/// </summary>
/// <remarks>
/// <para>
/// The obvious implementation — flatten the tree, sort, take N — allocates a list as long as the
/// whole filesystem. These methods keep a bounded min-heap of exactly <c>take</c> entries instead,
/// so peak memory is O(take) no matter how many files were scanned. Time is O(n log take).
/// </para>
/// <para>Reporting only. Nothing here deletes or modifies anything.</para>
/// </remarks>
public static class LargestItemsFinder
{
    /// <summary>
    /// The biggest files in the tree, largest first. Empty files are ignored, as are files the
    /// scan chose not to materialise (see <see cref="TreeScanOptions.MinimumFileSizeBytes"/>).
    /// </summary>
    public static IReadOnlyList<DirNode> LargestFiles(DirNode root, int take = 100) =>
        TopBySize(root, take, wantDirectories: false);

    /// <summary>
    /// The biggest folders in the tree by total subtree size, largest first.
    /// </summary>
    /// <remarks>
    /// <paramref name="root"/> itself is excluded: it is trivially the largest folder and tells
    /// the user nothing. Results are nested — a folder and its parent can both appear.
    /// </remarks>
    public static IReadOnlyList<DirNode> LargestFolders(DirNode root, int take = 100) =>
        TopBySize(root, take, wantDirectories: true);

    private static IReadOnlyList<DirNode> TopBySize(DirNode root, int take, bool wantDirectories)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (take <= 0) return [];

        // Min-heap: the smallest of the current best `take` sits at the top, ready to be evicted.
        var heap = new PriorityQueue<DirNode, long>(take);

        var stack = new Stack<DirNode>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var node = stack.Pop();

            if (!ReferenceEquals(node, root) && node.IsDirectory == wantDirectories && node.SizeBytes > 0)
                Offer(heap, node, take);

            if (!node.IsDirectory) continue;

            foreach (var child in node.Children)
            {
                // Looking for folders? File nodes are leaves, so there is nothing below them.
                if (wantDirectories && !child.IsDirectory) continue;
                stack.Push(child);
            }
        }

        // Draining a min-heap yields ascending sizes, so fill the array from the back to get
        // largest-first without a second sort.
        var ordered = new DirNode[heap.Count];
        for (int i = ordered.Length - 1; i >= 0; i--)
            ordered[i] = heap.Dequeue();

        return ordered;
    }

    private static void Offer(PriorityQueue<DirNode, long> heap, DirNode node, int take)
    {
        if (heap.Count < take)
        {
            heap.Enqueue(node, node.SizeBytes);
            return;
        }

        if (heap.TryPeek(out _, out long smallest) && node.SizeBytes > smallest)
            heap.EnqueueDequeue(node, node.SizeBytes);
    }
}
