namespace Ballast.Core.DiskAnalysis;

/// <summary>
/// One node placed on the treemap canvas. Plain numbers — no UI framework types — so the layout
/// can be unit tested and reused by any renderer.
/// </summary>
public sealed record TreemapTile(DirNode Node, double X, double Y, double Width, double Height)
{
    public double Right => X + Width;
    public double Bottom => Y + Height;
    public double Area => Width * Height;
}

/// <summary>
/// Squarified treemap layout (Bruls, Huizing and van Wijk, 2000).
///
/// <para>
/// Tiles are laid out in rows across the shorter side of the remaining rectangle. A row keeps
/// taking the next node while doing so improves the row's worst aspect ratio, and is flushed as
/// soon as it would get worse. That is what keeps tiles close to square — the naive
/// slice-and-dice alternative produces unreadable slivers as soon as sizes are uneven.
/// </para>
///
/// <para>
/// Pure geometry: no WinUI dependency, no allocation of anything but the returned tiles, and no
/// mutation of the nodes passed in.
/// </para>
/// </summary>
public static class TreemapLayout
{
    /// <summary>Anything thinner than this is not drawable, and is where divisions get dangerous.</summary>
    private const double Epsilon = 1e-9;

    /// <summary>
    /// Lays <paramref name="nodes"/> out inside the rectangle at
    /// (<paramref name="x"/>, <paramref name="y"/>).
    /// </summary>
    /// <remarks>
    /// Degenerate input yields an empty list rather than an exception or NaN geometry:
    /// no nodes, a non-positive or non-finite width or height, or nodes that are all empty.
    /// Individual nodes with a size of zero or less are dropped — a zero-area tile cannot be
    /// rendered or clicked, and keeping them would divide by zero on the aspect-ratio maths.
    /// Every returned tile is inside the requested rectangle.
    /// </remarks>
    public static IReadOnlyList<TreemapTile> Layout(
        IEnumerable<DirNode> nodes,
        double x,
        double y,
        double width,
        double height)
    {
        ArgumentNullException.ThrowIfNull(nodes);

        if (!double.IsFinite(x) || !double.IsFinite(y) || !IsDrawable(width) || !IsDrawable(height))
            return [];

        // Squarification requires descending order.
        var items = nodes
            .Where(n => n is not null && n.SizeBytes > 0)
            .OrderByDescending(n => n.SizeBytes)
            .ToArray();

        if (items.Length == 0) return [];

        double totalSize = 0d;
        foreach (var node in items) totalSize += node.SizeBytes; // double, so a full drive cannot overflow

        if (totalSize <= 0d) return [];

        // Convert byte counts to pixel areas once; from here on the algorithm is pure geometry.
        double pixelsPerByte = width * height / totalSize;
        var areas = new double[items.Length];
        for (int i = 0; i < items.Length; i++)
            areas[i] = items[i].SizeBytes * pixelsPerByte;

        var tiles = new List<TreemapTile>(items.Length);

        // The rectangle still to be filled, shrinking one row at a time.
        double rx = x, ry = y, rw = width, rh = height;
        int index = 0;

        while (index < items.Length)
        {
            double side = Math.Min(rw, rh);
            if (side <= Epsilon) break; // rounding has eaten the remaining space; nothing left to draw

            // Grow the row while the worst aspect ratio in it keeps improving.
            int end = index + 1;
            double rowArea = areas[index];
            double rowMin = areas[index];
            double rowMax = areas[index];

            while (end < items.Length)
            {
                double area = areas[end];
                double nextArea = rowArea + area;
                double nextMin = Math.Min(rowMin, area);
                double nextMax = Math.Max(rowMax, area);

                if (Worst(nextArea, nextMin, nextMax, side) > Worst(rowArea, rowMin, rowMax, side))
                    break;

                rowArea = nextArea;
                rowMin = nextMin;
                rowMax = nextMax;
                end++;
            }

            // The last row gets the whole remainder, so floating-point drift cannot leave a gap.
            bool isLastRow = end == items.Length;

            if (rw >= rh)
            {
                // Shorter side is the height: the row is a vertical strip down the left edge,
                // with its tiles stacked top to bottom.
                double thickness = isLastRow ? rw : Math.Min(rw, rowArea / rh);
                double cursor = ry;

                for (int i = index; i < end; i++)
                {
                    double remaining = Math.Max(0d, ry + rh - cursor);
                    double tileHeight = thickness > Epsilon ? areas[i] / thickness : 0d;
                    if (i == end - 1 || tileHeight > remaining) tileHeight = remaining;

                    tiles.Add(new TreemapTile(items[i], rx, cursor, thickness, tileHeight));
                    cursor += tileHeight;
                }

                rx += thickness;
                rw = Math.Max(0d, rw - thickness);
            }
            else
            {
                // Shorter side is the width: the row is a horizontal strip across the top,
                // with its tiles laid left to right.
                double thickness = isLastRow ? rh : Math.Min(rh, rowArea / rw);
                double cursor = rx;

                for (int i = index; i < end; i++)
                {
                    double remaining = Math.Max(0d, rx + rw - cursor);
                    double tileWidth = thickness > Epsilon ? areas[i] / thickness : 0d;
                    if (i == end - 1 || tileWidth > remaining) tileWidth = remaining;

                    tiles.Add(new TreemapTile(items[i], cursor, ry, tileWidth, thickness));
                    cursor += tileWidth;
                }

                ry += thickness;
                rh = Math.Max(0d, rh - thickness);
            }

            index = end;
        }

        return tiles;
    }

    /// <summary>
    /// Worst (largest) aspect ratio produced by laying a row of total area
    /// <paramref name="rowArea"/> along a side of length <paramref name="side"/>, given the
    /// smallest and largest tile areas in it. This is the <c>worst()</c> function from the paper:
    /// <c>max(side² · max / rowArea², rowArea² / (side² · min))</c>.
    /// </summary>
    /// <returns>1 for a perfect square, larger for anything more elongated.</returns>
    private static double Worst(double rowArea, double min, double max, double side)
    {
        // A degenerate row is infinitely bad, which also keeps the caller's comparison meaningful
        // without ever producing NaN.
        if (rowArea <= Epsilon || min <= Epsilon || side <= Epsilon)
            return double.PositiveInfinity;

        double rowAreaSquared = rowArea * rowArea;
        double sideSquared = side * side;

        return Math.Max(sideSquared * max / rowAreaSquared, rowAreaSquared / (sideSquared * min));
    }

    private static bool IsDrawable(double length) => double.IsFinite(length) && length > Epsilon;
}
