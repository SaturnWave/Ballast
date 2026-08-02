using Ballast.Core.DiskAnalysis;
using Xunit;

namespace Ballast.Tests;

public class TreemapLayoutTests
{
    private static DirNode Node(string name, long size) =>
        new() { Name = name, FullPath = @"C:\x\" + name, SizeBytes = size, IsDirectory = true };

    private static List<DirNode> Nodes(params long[] sizes) =>
        sizes.Select((s, i) => Node($"n{i}", s)).ToList();

    [Fact]
    public void Tiles_stay_inside_the_requested_rectangle()
    {
        var tiles = TreemapLayout.Layout(Nodes(500, 300, 120, 60, 12, 8, 3, 1), 10, 20, 800, 400);

        Assert.NotEmpty(tiles);
        foreach (var t in tiles)
        {
            Assert.True(t.X >= 10 - 1e-6, $"{t.Node.Name} escaped left");
            Assert.True(t.Y >= 20 - 1e-6, $"{t.Node.Name} escaped top");
            Assert.True(t.Right <= 810 + 1e-6, $"{t.Node.Name} escaped right");
            Assert.True(t.Bottom <= 420 + 1e-6, $"{t.Node.Name} escaped bottom");
            Assert.True(t.Width >= 0 && t.Height >= 0);
            Assert.True(double.IsFinite(t.X) && double.IsFinite(t.Y));
            Assert.True(double.IsFinite(t.Width) && double.IsFinite(t.Height));
        }
    }

    [Fact]
    public void Every_node_gets_exactly_one_tile()
    {
        var nodes = Nodes(100, 90, 80, 70, 5, 4, 3, 2, 1);
        var tiles = TreemapLayout.Layout(nodes, 0, 0, 600, 500);

        Assert.Equal(nodes.Count, tiles.Count);
        Assert.Equal(nodes.Count, tiles.Select(t => t.Node).Distinct().Count());
    }

    [Fact]
    public void Tiles_fill_the_rectangle_without_overlapping()
    {
        var tiles = TreemapLayout.Layout(Nodes(400, 250, 200, 90, 40, 20), 0, 0, 400, 300);

        double totalArea = tiles.Sum(t => t.Area);
        Assert.Equal(400d * 300d, totalArea, 0.5);

        // Pairwise overlap check on a small set is cheap and catches off-by-one packing bugs.
        for (int i = 0; i < tiles.Count; i++)
        {
            for (int j = i + 1; j < tiles.Count; j++)
            {
                var a = tiles[i];
                var b = tiles[j];

                double overlapW = Math.Min(a.Right, b.Right) - Math.Max(a.X, b.X);
                double overlapH = Math.Min(a.Bottom, b.Bottom) - Math.Max(a.Y, b.Y);
                double overlap = Math.Max(0, overlapW) * Math.Max(0, overlapH);

                Assert.True(overlap < 0.5,
                    $"{a.Node.Name} overlaps {b.Node.Name} by {overlap:0.###} px²");
            }
        }
    }

    [Fact]
    public void Tile_area_is_proportional_to_node_size()
    {
        var nodes = Nodes(600, 300, 100);
        var tiles = TreemapLayout.Layout(nodes, 0, 0, 1000, 100);

        double canvas = 1000d * 100d;
        foreach (var tile in tiles)
        {
            double expected = canvas * tile.Node.SizeBytes / 1000d;
            Assert.Equal(expected, tile.Area, expected * 0.02); // within 2%
        }
    }

    [Fact]
    public void Larger_nodes_are_never_given_smaller_tiles()
    {
        var tiles = TreemapLayout.Layout(Nodes(1000, 500, 250, 125, 60, 30), 0, 0, 700, 450);
        var ordered = tiles.OrderByDescending(t => t.Node.SizeBytes).ToList();

        for (int i = 1; i < ordered.Count; i++)
            Assert.True(ordered[i - 1].Area >= ordered[i].Area - 0.5,
                "a bigger folder was drawn smaller than a smaller one");
    }

    [Theory]
    [InlineData(0, 100)]
    [InlineData(100, 0)]
    [InlineData(-50, 100)]
    [InlineData(double.NaN, 100)]
    [InlineData(double.PositiveInfinity, 100)]
    public void Degenerate_rectangles_yield_no_tiles_instead_of_throwing(double w, double h)
        => Assert.Empty(TreemapLayout.Layout(Nodes(10, 5), 0, 0, w, h));

    [Fact]
    public void Empty_and_zero_sized_input_is_handled()
    {
        Assert.Empty(TreemapLayout.Layout([], 0, 0, 100, 100));
        Assert.Empty(TreemapLayout.Layout(Nodes(0, 0, 0), 0, 0, 100, 100));

        // Zero-size nodes are dropped, the real one still gets laid out.
        var mixed = TreemapLayout.Layout(Nodes(0, 50, 0), 0, 0, 100, 100);
        Assert.Single(mixed);
        Assert.Equal(50, mixed[0].Node.SizeBytes);
    }

    [Fact]
    public void A_single_node_takes_the_whole_rectangle()
    {
        var tiles = TreemapLayout.Layout(Nodes(42), 5, 7, 200, 150);

        Assert.Single(tiles);
        Assert.Equal(5, tiles[0].X, 1e-6);
        Assert.Equal(7, tiles[0].Y, 1e-6);
        Assert.Equal(200, tiles[0].Width, 1e-6);
        Assert.Equal(150, tiles[0].Height, 1e-6);
    }

    [Fact]
    public void Highly_skewed_sizes_still_produce_reasonable_aspect_ratios()
    {
        // One huge folder and many tiny ones is the pathological case for slice-and-dice.
        var sizes = new long[] { 1_000_000 }.Concat(Enumerable.Repeat(1_000L, 40)).ToArray();
        var tiles = TreemapLayout.Layout(Nodes(sizes), 0, 0, 900, 600);

        Assert.Equal(41, tiles.Count);

        // The dominant tile should be recognisably chunky, not a sliver.
        var biggest = tiles.OrderByDescending(t => t.Node.SizeBytes).First();
        double ratio = Math.Max(biggest.Width, biggest.Height) /
                       Math.Max(1e-9, Math.Min(biggest.Width, biggest.Height));
        Assert.True(ratio < 4, $"dominant tile aspect ratio was {ratio:0.##}");
    }

    [Fact]
    public void Layout_does_not_mutate_the_input_nodes()
    {
        var nodes = Nodes(300, 200, 100);
        var before = nodes.Select(n => n.SizeBytes).ToArray();

        TreemapLayout.Layout(nodes, 0, 0, 500, 500);

        Assert.Equal(before, nodes.Select(n => n.SizeBytes).ToArray());
    }
}
