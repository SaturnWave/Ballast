using Ballast.Core.DiskAnalysis;
using Ballast.Core.Util;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;
using Windows.UI;

namespace Ballast.App.Controls;

/// <summary>Carries the node a treemap gesture landed on. <see cref="Node"/> is null when the pointer left the map.</summary>
public sealed class TreemapNodeEventArgs : EventArgs
{
    /// <summary>Wraps <paramref name="node"/>.</summary>
    public TreemapNodeEventArgs(DirNode? node) => Node = node;

    /// <summary>The node under the pointer, or null.</summary>
    public DirNode? Node { get; }
}

/// <summary>A right-click on a tile, with the point to anchor a flyout at.</summary>
public sealed class TreemapContextEventArgs : EventArgs
{
    /// <summary>Wraps <paramref name="node"/> and the <paramref name="position"/> it was clicked at.</summary>
    public TreemapContextEventArgs(DirNode node, Point position)
    {
        Node = node;
        Position = position;
    }

    /// <summary>The node that was right-clicked.</summary>
    public DirNode Node { get; }

    /// <summary>Pointer position, relative to the control.</summary>
    public Point Position { get; }
}

/// <summary>
/// One node's deletion risk, flattened to primitives so it can be held in a struct field and
/// handed to the UI without dragging a Core record type into markup-visible surfaces.
/// </summary>
internal readonly record struct RiskNote(int Level, string Title, string Reason);

/// <summary>
/// The <em>only</em> place in the UI layer that names <c>Ballast.Core.Util</c>'s risk API.
/// </summary>
/// <remarks>
/// Levels are carried as plain <see cref="int"/>s (1 = system, 5 = safe) everywhere above this
/// class. That is not squeamishness about the enum: a <see cref="DependencyProperty"/> and a
/// binding source both need types the XAML type-info generator can construct, and an <c>int</c>
/// mask is trivially both. Funnelling every call through here also means the risk assessor can be
/// renamed or resharpened without touching the control, the page or the view model.
/// </remarks>
internal static class RiskBridge
{
    /// <summary>Most dangerous level. Matches <c>DeletionRisk.System</c>.</summary>
    public const int Lowest = 1;

    /// <summary>Safest level. Matches <c>DeletionRisk.Safe</c>.</summary>
    public const int Highest = 5;

    /// <summary>Bit mask with every level visible.</summary>
    public const int AllMask = 0b11111;

    /// <summary>The single-bit mask for <paramref name="level"/>, for the filter mask.</summary>
    public static int MaskOf(int level) => 1 << (Clamp(level) - 1);

    /// <summary>True when <paramref name="mask"/> includes <paramref name="level"/>.</summary>
    public static bool IsVisible(int mask, int level) => (mask & MaskOf(level)) != 0;

    /// <summary>Classifies <paramref name="path"/>. Never throws — an unreadable path reads as risky.</summary>
    public static RiskNote Assess(string path, bool isDirectory)
    {
        try
        {
            RiskAssessment assessment = DeletionRiskAssessor.Assess(path, isDirectory);
            return new RiskNote((int)assessment.Level, assessment.Title, assessment.Reason);
        }
        catch (Exception)
        {
            // "We could not tell" has to mean "treat it as dangerous", the same rule
            // SystemPathGuard follows. A map that paints an unreadable path green is worse than
            // one that paints it amber.
            return new RiskNote(
                (int)DeletionRisk.Risky,
                ShortLabel((int)DeletionRisk.Risky),
                "This item could not be examined, so it is being treated as risky.");
        }
    }

    /// <summary>Two or three words naming <paramref name="level"/>, for a legend swatch.</summary>
    public static string ShortLabel(int level) => DeletionRiskAssessor.ShortLabel(LevelOf(level));

    /// <summary>A sentence explaining what <paramref name="level"/> means.</summary>
    public static string Describe(int level) => DeletionRiskAssessor.Describe(LevelOf(level));

    /// <summary>True when <paramref name="level"/> is no safer than <paramref name="ceiling"/>.</summary>
    public static bool IsAtOrBelow(int level, int ceiling) =>
        DeletionRiskAssessor.IsAtOrBelow(LevelOf(level), LevelOf(ceiling));

    private static DeletionRisk LevelOf(int level) => (DeletionRisk)Clamp(level);

    private static int Clamp(int level) => Math.Clamp(level, Lowest, Highest);
}

/// <summary>
/// A recursive treemap of a <see cref="DirNode"/> tree — the "where did my space go" view, coloured
/// by how dangerous each item is to delete rather than by what kind of file it is.
/// </summary>
/// <remarks>
/// <para>
/// Geometry comes entirely from <see cref="TreemapLayout"/> — the squarified algorithm is applied
/// once per level, to the children of each tile, inside that tile's rectangle. There is no layout
/// maths in this file at all.
/// </para>
/// <para>
/// Three rules keep the result readable rather than merely correct:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>No fringe.</b> Before a level is laid out, everything that would land below
/// <see cref="MinTopSide"/> / <see cref="MinNestedSide"/> is folded into a single "N smaller items"
/// tile. A hundred unclickable one-pixel slivers tell the user nothing; one honest tile does.
/// </item>
/// <item>
/// <b>Labels are measured, not estimated.</b> A tile is labelled only when the text actually fits
/// at its natural width, so nothing is ever drawn as a lone ellipsis, and the size line appears
/// only when there is genuinely room for a second line.
/// </item>
/// <item>
/// <b>Filtering dims, it never re-lays-out.</b> Hiding a risk level repaints in place, so the map
/// cannot reflow under the pointer and lose the user's place.
/// </item>
/// </list>
/// <para>
/// Cost is bounded four ways, because a whole-drive tree can nest very wide: a hard cap of
/// <see cref="MaxTiles"/> rectangles and <see cref="MaxChildrenPerTile"/> per level (past those,
/// nesting stops rather than the UI freezing); pooled visuals that are repositioned rather than
/// recreated; brushes shared per (risk, depth) pair rather than per tile; and manual hit-testing
/// against the flat tile list, so hover moves two overlay rectangles instead of touching the visual
/// tree. Risk verdicts are cached per path, so a repaint never re-asks.
/// </para>
/// <para>The tree passed in is never mutated — this control only measures and paints it.</para>
/// </remarks>
public sealed class TreemapControl : UserControl
{
    /// <summary>Ceiling on drawn rectangles. Past this, nesting stops rather than the UI freezing.</summary>
    public const int MaxTiles = 2000;

    /// <summary>Ceiling on tiles drawn inside one parent; the rest are aggregated.</summary>
    private const int MaxChildrenPerTile = 160;

    /// <summary>Smallest side a top-level tile may have. Below this it is folded into the aggregate.</summary>
    private const double MinTopSide = 9d;

    /// <summary>Smallest side a nested tile may have.</summary>
    private const double MinNestedSide = 7d;

    /// <summary>A tile must be at least this big before children are laid out inside it.</summary>
    private const double MinNestWidth = 40d;
    private const double MinNestHeight = 30d;

    /// <summary>Strip reserved at the top of a nesting tile so its own label stays readable.</summary>
    private const double HeaderHeight = 18d;

    /// <summary>Coarse gate applied before a label is measured, so tiny tiles cost nothing.</summary>
    private const double MinLabelWidth = 34d;
    private const double MinLabelHeight = 14d;

    /// <summary>Horizontal breathing room either side of a label.</summary>
    private const double LabelInset = 6d;

    /// <summary>How faint a tile goes when its risk level is filtered out.</summary>
    private const double MutedOpacity = 0.16d;

    /// <summary>Drill animation length. Long enough to follow, short enough never to feel modal.</summary>
    private const double ZoomMilliseconds = 200d;

    /// <summary>Sentinel level for the "N smaller items" tile, which has no single risk.</summary>
    private const int AggregateLevel = 0;

    /// <summary>Sentinel level for a tile whose verdict has not come back from the pool yet.</summary>
    private const int UnknownLevel = -1;

    /// <summary>
    /// Verdicts merged back into the map at a time. Small enough that the biggest tiles — which are
    /// laid out first — colour in almost at once, big enough not to repaint on every path.
    /// </summary>
    private const int RiskBatchSize = 256;

    private static readonly FontFamily _labelFont = new("Inter, Segoe UI Variable Text, Segoe UI");

    private static readonly Comparison<DirNode> _bySizeDescending =
        static (a, b) => b.SizeBytes.CompareTo(a.SizeBytes);

    /// <summary>Contract fallbacks, used when <c>Risk1Brush</c>..<c>Risk5Brush</c> are not resolvable.</summary>
    private static readonly Color[] _fallbackRiskColors =
    [
        Color.FromArgb(255, 0xB3, 0x26, 0x1E), // 1 system / never delete
        Color.FromArgb(255, 0xD4, 0x76, 0x1F), // 2 risky
        Color.FromArgb(255, 0xC9, 0xA2, 0x27), // 3 caution
        Color.FromArgb(255, 0x6E, 0x8B, 0x3D), // 4 probably safe
        Color.FromArgb(255, 0x3F, 0x7D, 0x58), // 5 safe to delete
    ];

    private static Windows.UI.ViewManagement.UISettings? _uiSettings;
    private static bool _motionProbeFailed;

    private readonly Grid _root = new();
    private readonly Grid _stage = new();
    private readonly CompositeTransform _stageTransform = new();
    private readonly Canvas _tileCanvas = new();
    private readonly Canvas _labelCanvas = new();
    private readonly Canvas _overlayCanvas = new();
    private readonly Border _hoverBorder = new();
    private readonly Border _selectionBorder = new();
    private readonly TextBlock _emptyLabel = new();
    private readonly ToolTip _toolTip = new();

    private readonly List<Border> _tilePool = [];
    private readonly List<TextBlock> _namePool = [];
    private readonly List<TextBlock> _sizePool = [];
    private readonly List<PlacedTile> _placed = [];
    private readonly Dictionary<SkinKey, TileSkin> _skins = [];

    /// <summary>Risk verdicts by path. Cleared with the tree, so a rescan re-asks.</summary>
    private readonly Dictionary<string, RiskNote> _riskCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Paths this layout needs a verdict for and has not got one for yet.</summary>
    private readonly List<RiskRequest> _pending = [];
    private readonly HashSet<string> _pendingPaths = new(StringComparer.OrdinalIgnoreCase);

    // Reused by the layout pass. Every use is consumed before the next call begins.
    private readonly List<DirNode> _keep = [];
    private readonly List<DirNode> _small = [];

    private readonly Color[] _riskColors = new Color[RiskBridge.Highest];
    private readonly DispatcherQueueTimer? _relayoutTimer;

    private SolidColorBrush _hoverStroke = new();
    private SolidColorBrush _hoverFill = new();
    private SolidColorBrush _selectionStroke = new();

    private Color _aggregateColor;
    private Storyboard? _zoom;

    private double _canvasWidth;
    private double _canvasHeight;
    private int _hoverIndex = -1;
    private int _selectionIndex = -1;
    private int _generation;
    private bool _isDark;
    private bool _animating;

    /// <summary>Builds the visual tree in code — there is no XAML template to keep in sync.</summary>
    public TreemapControl()
    {
        _root.Background = new SolidColorBrush(Colors.Transparent); // null would not be hit-testable

        // Everything that moves during a drill animation lives on the stage, so one transform
        // carries tiles, labels and the selection outline together.
        _stage.RenderTransform = _stageTransform;
        _stage.Children.Add(_tileCanvas);

        // Labels live on their own layer above every tile. Pooled visuals are created in whatever
        // order the first paint needed them, so relying on insertion order for z-order would make
        // the result depend on paint history. This makes it fixed.
        _labelCanvas.IsHitTestVisible = false;
        _stage.Children.Add(_labelCanvas);

        _overlayCanvas.IsHitTestVisible = false;
        _hoverBorder.Visibility = Visibility.Collapsed;
        _hoverBorder.BorderThickness = new Thickness(1);
        _hoverBorder.CornerRadius = new CornerRadius(3);
        _selectionBorder.Visibility = Visibility.Collapsed;
        _selectionBorder.BorderThickness = new Thickness(2);
        _selectionBorder.CornerRadius = new CornerRadius(3);
        _overlayCanvas.Children.Add(_hoverBorder);
        _overlayCanvas.Children.Add(_selectionBorder);
        _stage.Children.Add(_overlayCanvas);

        _root.Children.Add(_stage);

        _emptyLabel.HorizontalAlignment = HorizontalAlignment.Center;
        _emptyLabel.VerticalAlignment = VerticalAlignment.Center;
        _emptyLabel.FontFamily = _labelFont;
        _emptyLabel.FontSize = 13;
        _emptyLabel.IsHitTestVisible = false;
        _emptyLabel.Text = "Scan a drive to see its map.";
        _root.Children.Add(_emptyLabel);

        // One ToolTip instance, retargeted on hover. Re-registering per tile would churn, and
        // clearing it would mean handing SetToolTip a null it does not accept.
        _toolTip.IsEnabled = false;
        ToolTipService.SetToolTip(_root, _toolTip);

        Content = _root;
        IsTabStop = true;
        MinHeight = 160;
        ReadPalette();
        ApplyChromeBrushes();

        _relayoutTimer = DispatcherQueue?.CreateTimer();
        if (_relayoutTimer is not null)
        {
            _relayoutTimer.Interval = TimeSpan.FromMilliseconds(60);
            _relayoutTimer.IsRepeating = false;
            _relayoutTimer.Tick += (_, _) => Render();
        }

        SizeChanged += OnSizeChanged;
        ActualThemeChanged += OnActualThemeChanged;
        _root.PointerMoved += OnPointerMoved;
        _root.PointerExited += OnPointerExited;
        _root.Tapped += OnTapped;
        _root.RightTapped += OnRightTapped;
        KeyDown += OnKeyDown;
    }

    /// <summary>
    /// Identifies the <see cref="Root"/> dependency property.
    /// </summary>
    /// <remarks>
    /// Internal, along with every other <see cref="DirNode"/>-typed member here, and not by
    /// preference. The XAML type-info generator walks the public properties of any type used in
    /// markup and emits a <c>new T()</c> activator for each property type it finds;
    /// <see cref="DirNode"/> has <c>required</c> members, so that activator does not compile.
    /// Keeping these members internal keeps them out of the generated file. Nothing is lost —
    /// this control has exactly one consumer, in this assembly.
    /// </remarks>
    internal static readonly DependencyProperty RootProperty =
        DependencyProperty.Register(
            nameof(Root),
            typeof(DirNode),
            typeof(TreemapControl),
            new PropertyMetadata(null, OnRootChanged));

    /// <summary>Identifies the <see cref="MaxDepth"/> dependency property.</summary>
    public static readonly DependencyProperty MaxDepthProperty =
        DependencyProperty.Register(
            nameof(MaxDepth),
            typeof(int),
            typeof(TreemapControl),
            new PropertyMetadata(3, OnMaxDepthChanged));

    /// <summary>Identifies the <see cref="VisibleRiskMask"/> dependency property.</summary>
    public static readonly DependencyProperty VisibleRiskMaskProperty =
        DependencyProperty.Register(
            nameof(VisibleRiskMask),
            typeof(int),
            typeof(TreemapControl),
            new PropertyMetadata(RiskBridge.AllMask, OnVisibleRiskMaskChanged));

    /// <summary>
    /// The scanned tree to display. Setting it resets the drill-down to the root and clears the
    /// selection. Null empties the map. Assign from code — see <see cref="RootProperty"/> for why
    /// this cannot be bound in markup.
    /// </summary>
    internal DirNode? Root
    {
        get => (DirNode?)GetValue(RootProperty);
        set => SetValue(RootProperty, value);
    }

    /// <summary>
    /// How many levels of nesting to draw, counting the current node's children as level one.
    /// Clamped to 1..6; the default of 3 is the point where structure is legible without the map
    /// turning into noise.
    /// </summary>
    public int MaxDepth
    {
        get => (int)GetValue(MaxDepthProperty);
        set => SetValue(MaxDepthProperty, value);
    }

    /// <summary>
    /// Bit mask of the risk levels drawn at full strength: bit 0 is level 1 (system), bit 4 is
    /// level 5 (safe). Levels outside the mask are dimmed and unlabelled but keep their place, so
    /// changing the filter never reflows the map. Defaults to all five.
    /// </summary>
    public int VisibleRiskMask
    {
        get => (int)GetValue(VisibleRiskMaskProperty);
        set => SetValue(VisibleRiskMaskProperty, value);
    }

    /// <summary>
    /// The folder currently filling the map. Starts at <see cref="Root"/> and moves with
    /// <see cref="NavigateTo"/> and <see cref="NavigateUp"/>.
    /// </summary>
    internal DirNode? CurrentNode { get; private set; }

    /// <summary>The tile the user picked, or null. Folders are selected by right-click, files by click.</summary>
    internal DirNode? SelectedNode { get; private set; }

    /// <summary>True when <see cref="NavigateUp"/> would go somewhere.</summary>
    public bool CanNavigateUp =>
        CurrentNode is not null && !ReferenceEquals(CurrentNode, Root) && CurrentNode.Parent is not null;

    /// <summary>Raised when the pointer moves onto a different tile, or off the map (null node).</summary>
    public event EventHandler<TreemapNodeEventArgs>? TileHovered;

    /// <summary>Raised when the selection changes, including when it is cleared.</summary>
    public event EventHandler<TreemapNodeEventArgs>? TileSelected;

    /// <summary>Raised on right-click so the host can show a Reveal/Delete menu.</summary>
    public event EventHandler<TreemapContextEventArgs>? TileContextRequested;

    /// <summary>Raised when the drill-down moves, so the host can update its breadcrumbs and lists.</summary>
    public event EventHandler<TreemapNodeEventArgs>? CurrentNodeChanged;

    /// <summary>
    /// Drills into <paramref name="node"/>. A file navigates to its parent and is selected instead,
    /// which is what "show me this in the map" means. No-op when already there.
    /// </summary>
    public void NavigateTo(DirNode? node)
    {
        if (node is null) return;

        if (!node.IsDirectory)
        {
            if (node.Parent is { } parent) SetCurrentNode(parent);
            Select(node);
            return;
        }

        SetCurrentNode(node);
    }

    /// <summary>Moves up one folder. Returns false when already at the root.</summary>
    public bool NavigateUp()
    {
        if (!CanNavigateUp || CurrentNode?.Parent is not { } parent) return false;

        SetCurrentNode(parent);
        return true;
    }

    /// <summary>
    /// Sets the selection, from the map or from a list elsewhere on the page. A node that is not
    /// currently drawn is still remembered; only its highlight is missing.
    /// </summary>
    public void Select(DirNode? node)
    {
        if (ReferenceEquals(SelectedNode, node)) return;

        SelectedNode = node;
        _selectionIndex = IndexOf(node);
        UpdateOverlay(_selectionBorder, _selectionIndex, _selectionStroke, null);
        TileSelected?.Invoke(this, new TreemapNodeEventArgs(node));
    }

    /// <summary>
    /// Re-reads the tree and repaints. Call after the filesystem changed underneath the map — the
    /// nodes themselves are never re-measured here, so a stale subtree must be rescanned first.
    /// </summary>
    public void Refresh() => Render();

    /// <summary>
    /// The risk verdict for <paramref name="node"/>, from the same cache the map paints from, so
    /// the page's selection card can never disagree with the tile the user clicked.
    /// </summary>
    internal RiskNote RiskOf(DirNode node) => RiskFor(node);

    private static void OnRootChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var map = (TreemapControl)d;
        var root = e.NewValue as DirNode;

        map.SelectedNode = null;
        map._selectionIndex = -1;
        map._selectionBorder.Visibility = Visibility.Collapsed;
        map._hoverIndex = -1;
        map._hoverBorder.Visibility = Visibility.Collapsed;

        // A new scan can have moved, created or deleted anything, so last scan's verdicts are
        // hearsay. They are cheap to rebuild and expensive to be wrong about.
        map._riskCache.Clear();

        map.CurrentNode = root;
        map.CurrentNodeChanged?.Invoke(map, new TreemapNodeEventArgs(root));
        map.TileSelected?.Invoke(map, new TreemapNodeEventArgs(null));
        map.StopZoom();
        map.Render();
    }

    private static void OnMaxDepthChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((TreemapControl)d).Render();

    /// <summary>
    /// Repaints without re-laying-out. That is the whole point of the filter: the geometry the user
    /// is looking at must not move because they ticked a legend swatch.
    /// </summary>
    private static void OnVisibleRiskMaskChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var map = (TreemapControl)d;
        if (map._placed.Count > 0) map.Paint();
    }

    private void SetCurrentNode(DirNode node)
    {
        if (ReferenceEquals(CurrentNode, node)) return;

        DirNode? previous = CurrentNode;
        bool drillingDown = previous is not null && IsDescendantOf(node, previous);

        // Measured against the layout still on screen — after Render() it is gone.
        Rect? origin = drillingDown ? RectOf(node) : null;

        CurrentNode = node;
        _hoverIndex = -1;
        _hoverBorder.Visibility = Visibility.Collapsed;
        CurrentNodeChanged?.Invoke(this, new TreemapNodeEventArgs(node));
        Render();

        if (drillingDown)
        {
            // The tile the user clicked eases out to fill the canvas.
            if (origin is { } from) ZoomFrom(from);
            return;
        }

        // Going up (or jumping to an ancestor crumb): the whole map shrinks back into the tile the
        // old folder now occupies. That tile only exists once the new level has been laid out.
        if (previous is not null && IsDescendantOf(previous, node) &&
            ChildOnPathTo(node, previous) is { } anchor &&
            RectOf(anchor) is { } target)
        {
            ZoomInto(target);
        }
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        // The stage is transformed during a drill, so without a clip the animation would paint
        // over the card around it.
        _root.Clip = new RectangleGeometry
        {
            Rect = new Rect(0, 0, Math.Max(0, e.NewSize.Width), Math.Max(0, e.NewSize.Height)),
        };

        // A window drag fires this continuously. Repainting up to 2000 rectangles on every tick
        // would stutter, so coalesce into one paint once the drag settles.
        if (_placed.Count == 0 || _relayoutTimer is null)
        {
            Render();
            return;
        }

        _relayoutTimer.Start();
    }

    private void OnActualThemeChanged(FrameworkElement sender, object args)
    {
        _isDark = ActualTheme == ElementTheme.Dark;
        _skins.Clear();
        ReadPalette();
        ApplyChromeBrushes();

        // Colour is not geometry: a theme flip only needs new brushes on the same rectangles.
        if (_placed.Count > 0) Paint();
    }

    // ===================================================================== layout

    private void Render()
    {
        _relayoutTimer?.Stop();
        StopZoom();

        double width = _tileCanvas.ActualWidth > 0 ? _tileCanvas.ActualWidth : ActualWidth;
        double height = _tileCanvas.ActualHeight > 0 ? _tileCanvas.ActualHeight : ActualHeight;

        bool themeIsDark = ActualTheme == ElementTheme.Dark;
        if (themeIsDark != _isDark)
        {
            _isDark = themeIsDark;
            _skins.Clear();
            ReadPalette();
            ApplyChromeBrushes();
        }

        _placed.Clear();
        _pending.Clear();
        _pendingPaths.Clear();
        _canvasWidth = width;
        _canvasHeight = height;

        // Anything still being judged for the layout we are about to throw away is now answering a
        // question nobody asked.
        _generation++;

        if (CurrentNode is not null && double.IsFinite(width) && double.IsFinite(height) &&
            width > 4 && height > 4)
        {
            BuildLayout(width, height);
        }

        Paint();
        StartRiskWarmup();

        bool empty = _placed.Count == 0;
        _emptyLabel.Visibility = empty ? Visibility.Visible : Visibility.Collapsed;
        _emptyLabel.Text = CurrentNode is null
            ? "Scan a drive to see its map."
            : $"Nothing measurable inside {CurrentNode.Name}.";

        // Overlay indices are positions in _placed, which we just rebuilt.
        _hoverIndex = -1;
        _hoverBorder.Visibility = Visibility.Collapsed;
        _selectionIndex = IndexOf(SelectedNode);
        UpdateOverlay(_selectionBorder, _selectionIndex, _selectionStroke, null);
    }

    /// <summary>
    /// Fills <see cref="_placed"/> breadth-first: a whole level is laid out before the next one
    /// starts, so when the tile budget runs out the map is uniformly shallow rather than deep in
    /// one corner and flat everywhere else.
    /// </summary>
    private void BuildLayout(double width, double height)
    {
        DirNode current = CurrentNode!;
        int maxDepth = Math.Clamp(MaxDepth, 1, 6);

        // A file (or an empty folder) has nothing inside it, so it is its own single tile.
        IReadOnlyList<DirNode> topLevel = current.HasChildren ? current.Children : [current];

        var level = new List<int>();
        bool budgetLeft = Emit(LayoutLevel(topLevel, 0, 0, width, height, 0), 0, maxDepth, level);

        for (int depth = 1; depth < maxDepth && level.Count > 0; depth++)
        {
            var next = new List<int>(level.Count * 4);

            foreach (int index in level)
            {
                PlacedTile parent = _placed[index];
                if (!parent.WillNest) continue;

                if (!budgetLeft)
                {
                    // No room left to draw children, so do not pretend there are any.
                    _placed[index] = parent with { WillNest = false };
                    continue;
                }

                double pad = depth == 1 ? 4d : 2.5d;
                double ix = parent.X + pad;
                double iy = parent.Y + pad + parent.Header;
                double iw = parent.Width - (pad * 2);
                double ih = parent.Height - (pad * 2) - parent.Header;

                int before = _placed.Count;

                if (iw > MinNestedSide && ih > MinNestedSide)
                {
                    budgetLeft = Emit(
                        LayoutLevel(parent.Node.Children, ix, iy, iw, ih, depth),
                        depth,
                        maxDepth,
                        next);
                }

                if (_placed.Count == before)
                    _placed[index] = parent with { WillNest = false };
            }

            level = next;
        }
    }

    /// <summary>
    /// Lays one level out, folding everything that would be too small to see into a single
    /// "N smaller items" tile first.
    /// </summary>
    /// <remarks>
    /// The fold is done on <em>area</em>, before the layout runs, rather than by dropping slivers
    /// afterwards. Dropping loses the bytes — the map then silently under-reports the folder — while
    /// folding keeps every byte on screen and honest, in one tile the user can actually point at.
    /// The threshold is derived from the rectangle being filled, so the same folder aggregates less
    /// as the window grows, which is what a reader expects.
    /// </remarks>
    private IReadOnlyList<TreemapTile> LayoutLevel(
        IReadOnlyList<DirNode> children,
        double x,
        double y,
        double width,
        double height,
        int depth)
    {
        if (children.Count == 0) return [];

        _keep.Clear();
        _small.Clear();

        double area = width * height;
        double minSide = depth == 0 ? MinTopSide : MinNestedSide;

        // 1.6x, not 1x: a tile with exactly minSide-squared of area is usually a long thin sliver
        // rather than a small square, and a sliver is what we are trying to be rid of.
        double minArea = minSide * minSide * 1.6d;

        long total = 0;
        foreach (DirNode child in children)
        {
            if (child.SizeBytes > 0) total += child.SizeBytes;
        }

        if (total <= 0 || area <= 0) return [];

        // Bytes that would buy exactly minArea pixels in this rectangle.
        double threshold = minArea / area * total;

        foreach (DirNode child in children)
        {
            if (child.SizeBytes <= 0) continue;

            if (child.SizeBytes >= threshold) _keep.Add(child);
            else _small.Add(child);
        }

        // A folder with thousands of same-sized children would otherwise pass the area test and eat
        // the whole tile budget in one level.
        if (_keep.Count > MaxChildrenPerTile)
        {
            _keep.Sort(_bySizeDescending);

            for (int i = MaxChildrenPerTile; i < _keep.Count; i++) _small.Add(_keep[i]);

            _keep.RemoveRange(MaxChildrenPerTile, _keep.Count - MaxChildrenPerTile);
        }

        if (_small.Count == 1)
        {
            // One extra tile is not a fringe. Aggregating it would replace a real, nameable item
            // with a euphemism for no gain at all.
            _keep.Add(_small[0]);
        }
        else if (_small.Count > 1)
        {
            long folded = 0;
            foreach (DirNode child in _small) folded += child.SizeBytes;

            if (folded > 0) _keep.Add(Aggregate(_small.Count, folded));
        }

        return TreemapLayout.Layout(_keep, x, y, width, height);
    }

    /// <summary>
    /// A synthetic stand-in for the items too small to draw. Parented to nothing on purpose: it is
    /// not part of the scanned tree, must never be navigated into, selected or deleted, and nothing
    /// that walks parents should ever meet it.
    /// </summary>
    private static DirNode Aggregate(int count, long bytes) => new()
    {
        Name = $"{count:N0} smaller items",
        FullPath = string.Empty,
        IsDirectory = false,
        SizeBytes = bytes,
        FileCount = count,
    };

    /// <summary>Records the drawable tiles of one level. Returns false once the budget is spent.</summary>
    private bool Emit(IReadOnlyList<TreemapTile> tiles, int depth, int maxDepth, List<int> sink)
    {
        double minSide = depth == 0 ? MinTopSide : MinNestedSide;

        foreach (TreemapTile tile in tiles)
        {
            if (_placed.Count >= MaxTiles) return false;

            // Aggregation works on area, so a wide-but-thin tile can still come out of the
            // squarifier. Those are dropped rather than drawn as a line.
            if (tile.Width < minSide || tile.Height < minSide) continue;

            bool aggregate = tile.Node.Parent is null && tile.Node.FullPath.Length == 0;

            bool nest =
                !aggregate &&
                depth + 1 < maxDepth &&
                tile.Node.IsDirectory &&
                tile.Node.HasChildren &&
                tile.Width >= MinNestWidth &&
                tile.Height >= MinNestHeight;

            double header = nest && tile.Width >= 58 && tile.Height >= 44 ? HeaderHeight : 0d;

            sink.Add(_placed.Count);
            _placed.Add(new PlacedTile(
                tile.Node,
                tile.X,
                tile.Y,
                tile.Width,
                tile.Height,
                depth,
                header,
                nest,
                aggregate,
                aggregate ? AggregateLevel : LevelFor(tile.Node)));
        }

        return true;
    }

    // ===================================================================== painting

    private void Paint()
    {
        int tiles = 0, names = 0, sizes = 0;
        int mask = VisibleRiskMask;

        foreach (PlacedTile placed in _placed)
        {
            TileSkin skin = SkinFor(placed);

            // An unjudged tile is never dimmed: the filter can only hide what it knows about, and
            // hiding something because its verdict has not arrived yet would be a lie.
            bool muted = placed.Level >= RiskBridge.Lowest && !RiskBridge.IsVisible(mask, placed.Level);

            Border border = Rent(_tilePool, _tileCanvas, tiles, static () => new Border
            {
                IsHitTestVisible = false, // one manual hit-test beats 2000 subscriptions
            });

            bool hairline = placed.Width >= 5 && placed.Height >= 5;
            border.Width = placed.Width;
            border.Height = placed.Height;
            border.Background = skin.Fill;
            border.BorderBrush = skin.Edge;
            border.BorderThickness = new Thickness(hairline ? 1 : 0);
            border.CornerRadius = new CornerRadius(placed.Depth == 0 ? 4 : 2);
            border.Opacity = muted ? MutedOpacity : 1d;
            border.Visibility = Visibility.Visible;
            Canvas.SetLeft(border, placed.X);
            Canvas.SetTop(border, placed.Y);
            tiles++;

            // A filtered-out tile keeps its place but says nothing: a label at 16% opacity is
            // unreadable noise, and reading it is not what the user asked for.
            if (muted) continue;

            // A label buried under a nested child is worse than no label at all. Draw one only
            // where it will actually be seen: in a reserved header strip, or on a leaf tile that
            // has nothing painted on top of it.
            bool headerMode = placed.Header >= HeaderHeight;
            if (!headerMode && placed.WillNest) continue;

            if (placed.Width < MinLabelWidth || placed.Height < MinLabelHeight) continue;

            double inner = placed.Width - (LabelInset * 2);
            if (inner <= 0) continue;

            double band = headerMode ? placed.Header : placed.Height - 4;

            TextBlock name = Rent(_namePool, _labelCanvas, names, static () => new TextBlock
            {
                IsHitTestVisible = false,
                FontFamily = _labelFont,
                TextWrapping = TextWrapping.NoWrap,
                TextTrimming = TextTrimming.None,
            });

            name.FontSize = placed.Depth == 0 ? 12.5 : 11.5;
            name.FontWeight = placed.Depth == 0 ? FontWeights.SemiBold : FontWeights.Normal;
            name.Foreground = skin.Text;
            name.Opacity = 1d;

            // In header mode the size shares the one strip, because a second line would land on
            // top of the children this tile just reserved space for. It is only worth trying when
            // both halves fit; otherwise fall back to the name alone.
            bool combined = headerMode && Fits(name, $"{placed.Node.Name}   {SizeOf(placed)}", inner, band);

            if (!combined && !Fits(name, placed.Node.Name, inner, band))
            {
                // Measured, not guessed: this tile genuinely cannot hold its own name, so it gets
                // no label rather than a lone ellipsis. The pooled block is left for the next tile.
                name.Visibility = Visibility.Collapsed;
                continue;
            }

            double nameHeight = name.DesiredSize.Height;
            Canvas.SetLeft(name, placed.X + LabelInset);
            Canvas.SetTop(name, placed.Y + (headerMode ? Math.Max(0, (placed.Header - nameHeight) / 2) : 3));
            names++;

            if (headerMode) continue;

            TextBlock size = Rent(_sizePool, _labelCanvas, sizes, static () => new TextBlock
            {
                IsHitTestVisible = false,
                FontFamily = _labelFont,
                FontSize = 11,
                TextWrapping = TextWrapping.NoWrap,
                TextTrimming = TextTrimming.None,
                Opacity = 0.85,
            });

            size.Foreground = skin.Text;

            // Second line only when there is honestly room for one under the first.
            if (!Fits(size, SizeOf(placed), inner, placed.Height - nameHeight - 6))
            {
                size.Visibility = Visibility.Collapsed;
                continue;
            }

            Canvas.SetLeft(size, placed.X + LabelInset);
            Canvas.SetTop(size, placed.Y + nameHeight + 3);
            sizes++;
        }

        Hide(_tilePool, tiles);
        Hide(_namePool, names);
        Hide(_sizePool, sizes);
    }

    /// <summary>
    /// Puts <paramref name="text"/> into <paramref name="block"/> and reports whether it fits the
    /// space given, at its natural size.
    /// </summary>
    /// <remarks>
    /// A <see cref="UIElement.Measure(Size)"/> against an unconstrained box is the only way to know:
    /// glyph widths depend on the font that actually resolved, the user's text scaling and the
    /// string itself, none of which a character count can stand in for. The block is left
    /// <see cref="Visibility.Visible"/> with its width unset, because a collapsed element measures
    /// to zero and a fixed width would make the answer trivially yes.
    /// </remarks>
    private static bool Fits(TextBlock block, string text, double availableWidth, double availableHeight)
    {
        block.Text = text;
        block.Width = double.NaN;
        block.Visibility = Visibility.Visible;
        block.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));

        Size desired = block.DesiredSize;
        return desired.Width <= availableWidth && desired.Height <= availableHeight;
    }

    private static string SizeOf(PlacedTile placed) => ByteFormatter.Format(placed.Node.SizeBytes);

    /// <summary>
    /// Hands back pooled visual <paramref name="index"/>, creating and parenting it on first use.
    /// The painter walks the pools in step with its own counters, so this is O(1) and every paint
    /// after the first adds nothing to the visual tree at all.
    /// </summary>
    private static T Rent<T>(List<T> pool, Canvas host, int index, Func<T> factory)
        where T : FrameworkElement
    {
        if (index < pool.Count) return pool[index];

        T created = factory();
        pool.Add(created);
        host.Children.Add(created);
        return created;
    }

    /// <summary>Collapses the tail of a pool that this paint did not need. Nothing is removed.</summary>
    private static void Hide<T>(List<T> pool, int used)
        where T : FrameworkElement
    {
        for (int i = used; i < pool.Count; i++)
        {
            if (pool[i].Visibility == Visibility.Visible) pool[i].Visibility = Visibility.Collapsed;
        }
    }

    // ===================================================================== interaction

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        // Mid-drill the tiles on screen are not where _placed says they are, so a hover would
        // highlight the wrong rectangle. 200ms of no hover is better than 200ms of a lie.
        if (_animating) return;

        int index = HitTest(e.GetCurrentPoint(_root).Position);
        if (index == _hoverIndex) return;

        _hoverIndex = index;
        UpdateOverlay(_hoverBorder, index, _hoverStroke, _hoverFill);

        if (index < 0)
        {
            _toolTip.IsEnabled = false;
            TileHovered?.Invoke(this, new TreemapNodeEventArgs(null));
            return;
        }

        PlacedTile tile = _placed[index];
        _toolTip.Content = Describe(tile);
        _toolTip.IsEnabled = true;

        // The aggregate is not a real node, so the page must not be told the pointer is over one.
        TileHovered?.Invoke(this, new TreemapNodeEventArgs(tile.IsAggregate ? null : tile.Node));
    }

    /// <summary>The tooltip body: what it is, how big, how many, and why it is that colour.</summary>
    private string Describe(PlacedTile tile)
    {
        DirNode node = tile.Node;

        if (tile.IsAggregate)
        {
            return
                $"{node.Name}\n{ByteFormatter.Format(node.SizeBytes)} in total\n" +
                "Each one is too small to draw at this size. Open the folder to see them.";
        }

        string what = node.IsDirectory
            ? $"Folder - {ByteFormatter.Format(node.SizeBytes)} across {node.FileCount:N0} files"
            : $"File - {ByteFormatter.Format(node.SizeBytes)}";

        RiskNote risk = RiskFor(node);
        return $"{node.FullPath}\n{what}\n{risk.Title} - {risk.Reason}";
    }

    private void OnPointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (_hoverIndex < 0) return;

        _hoverIndex = -1;
        _hoverBorder.Visibility = Visibility.Collapsed;
        _toolTip.IsEnabled = false;
        TileHovered?.Invoke(this, new TreemapNodeEventArgs(null));
    }

    private void OnTapped(object sender, TappedRoutedEventArgs e)
    {
        if (_animating) return;

        int index = HitTest(e.GetPosition(_root));
        if (index < 0) return;

        PlacedTile tile = _placed[index];
        Focus(FocusState.Programmatic);

        // The aggregate stands for items that are not drawn; there is nothing to open or select.
        if (tile.IsAggregate) return;

        if (tile.Node.IsDirectory && tile.Node.HasChildren)
        {
            SetCurrentNode(tile.Node);
            return;
        }

        Select(tile.Node);
    }

    private void OnRightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if (_animating) return;

        Point position = e.GetPosition(_root);
        int index = HitTest(position);
        if (index < 0) return;

        PlacedTile tile = _placed[index];
        if (tile.IsAggregate) return;

        // Selecting first means the host's menu and its Delete button always agree on the target.
        Select(tile.Node);
        TileContextRequested?.Invoke(this, new TreemapContextEventArgs(tile.Node, position));
        e.Handled = true;
    }

    private void OnKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key is not (Windows.System.VirtualKey.Back or Windows.System.VirtualKey.Escape)) return;

        e.Handled = NavigateUp();
    }

    /// <summary>
    /// Deepest tile under <paramref name="point"/>, or -1. Children are appended after their
    /// parent, so scanning backwards finds the topmost drawn tile first.
    /// </summary>
    private int HitTest(Point point)
    {
        for (int i = _placed.Count - 1; i >= 0; i--)
        {
            PlacedTile tile = _placed[i];

            if (point.X >= tile.X && point.X < tile.X + tile.Width &&
                point.Y >= tile.Y && point.Y < tile.Y + tile.Height)
            {
                return i;
            }
        }

        return -1;
    }

    private int IndexOf(DirNode? node)
    {
        if (node is null) return -1;

        for (int i = 0; i < _placed.Count; i++)
        {
            if (ReferenceEquals(_placed[i].Node, node)) return i;
        }

        return -1;
    }

    private Rect? RectOf(DirNode node)
    {
        int index = IndexOf(node);
        if (index < 0) return null;

        PlacedTile tile = _placed[index];
        return new Rect(tile.X, tile.Y, tile.Width, tile.Height);
    }

    private void UpdateOverlay(Border overlay, int index, Brush stroke, Brush? fill)
    {
        if (index < 0 || index >= _placed.Count)
        {
            overlay.Visibility = Visibility.Collapsed;
            return;
        }

        PlacedTile tile = _placed[index];
        overlay.Width = tile.Width;
        overlay.Height = tile.Height;
        overlay.BorderBrush = stroke;
        overlay.Background = fill;
        overlay.Visibility = Visibility.Visible;
        Canvas.SetLeft(overlay, tile.X);
        Canvas.SetTop(overlay, tile.Y);
    }

    private static bool IsDescendantOf(DirNode node, DirNode ancestor)
    {
        for (DirNode? walk = node.Parent; walk is not null; walk = walk.Parent)
        {
            if (ReferenceEquals(walk, ancestor)) return true;
        }

        return false;
    }

    /// <summary>The direct child of <paramref name="ancestor"/> that <paramref name="node"/> sits under.</summary>
    private static DirNode? ChildOnPathTo(DirNode ancestor, DirNode node)
    {
        for (DirNode? walk = node; walk is not null; walk = walk.Parent)
        {
            if (ReferenceEquals(walk.Parent, ancestor)) return walk;
        }

        return null;
    }

    // ===================================================================== drill animation

    /// <summary>Grows the newly drawn level out of <paramref name="origin"/>, the tile just clicked.</summary>
    private void ZoomFrom(Rect origin)
    {
        if (_canvasWidth <= 0 || _canvasHeight <= 0 || origin.Width <= 0.5 || origin.Height <= 0.5)
            return;

        Play(
            origin.Width / _canvasWidth,
            origin.Height / _canvasHeight,
            origin.X,
            origin.Y);
    }

    /// <summary>Shrinks the map back into <paramref name="target"/>, where the old folder now sits.</summary>
    private void ZoomInto(Rect target)
    {
        if (_canvasWidth <= 0 || _canvasHeight <= 0 || target.Width <= 0.5 || target.Height <= 0.5)
            return;

        double scaleX = _canvasWidth / target.Width;
        double scaleY = _canvasHeight / target.Height;

        Play(scaleX, scaleY, -target.X * scaleX, -target.Y * scaleY);
    }

    /// <summary>
    /// Eases the stage from the given transform back to identity.
    /// </summary>
    /// <remarks>
    /// A transform on one container, not a per-frame relayout: the tiles are laid out exactly once
    /// and the compositor does the rest off the UI thread. Animating <c>Canvas.Left</c> on two
    /// thousand borders, or re-running the squarifier on a timer, would do neither.
    /// </remarks>
    private void Play(double scaleX, double scaleY, double translateX, double translateY)
    {
        StopZoom();

        if (!AnimationsAllowed ||
            !double.IsFinite(scaleX) || !double.IsFinite(scaleY) ||
            !double.IsFinite(translateX) || !double.IsFinite(translateY) ||
            scaleX <= 0 || scaleY <= 0)
        {
            return;
        }

        // A tile a couple of pixels across would otherwise start the map at 400x and read as a
        // flash rather than a movement.
        scaleX = Math.Clamp(scaleX, 0.02d, 40d);
        scaleY = Math.Clamp(scaleY, 0.02d, 40d);

        _stageTransform.ScaleX = scaleX;
        _stageTransform.ScaleY = scaleY;
        _stageTransform.TranslateX = translateX;
        _stageTransform.TranslateY = translateY;

        var storyboard = new Storyboard();
        storyboard.Children.Add(Leg(nameof(CompositeTransform.ScaleX), scaleX, 1d));
        storyboard.Children.Add(Leg(nameof(CompositeTransform.ScaleY), scaleY, 1d));
        storyboard.Children.Add(Leg(nameof(CompositeTransform.TranslateX), translateX, 0d));
        storyboard.Children.Add(Leg(nameof(CompositeTransform.TranslateY), translateY, 0d));
        storyboard.Completed += OnZoomCompleted;

        _zoom = storyboard;
        _animating = true;
        storyboard.Begin();
    }

    private DoubleAnimation Leg(string property, double from, double to)
    {
        var animation = new DoubleAnimation
        {
            From = from,
            To = to,
            Duration = new Duration(TimeSpan.FromMilliseconds(ZoomMilliseconds)),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };

        Storyboard.SetTarget(animation, _stageTransform);
        Storyboard.SetTargetProperty(animation, property);
        return animation;
    }

    private void OnZoomCompleted(object? sender, object e) => StopZoom();

    /// <summary>Ends any drill animation and puts the stage back at rest. Safe to call at any time.</summary>
    private void StopZoom()
    {
        if (_zoom is not null)
        {
            _zoom.Completed -= OnZoomCompleted;
            _zoom.Stop();
            _zoom = null;
        }

        _animating = false;
        _stageTransform.ScaleX = 1d;
        _stageTransform.ScaleY = 1d;
        _stageTransform.TranslateX = 0d;
        _stageTransform.TranslateY = 0d;
    }

    /// <summary>
    /// False when the user has asked Windows to reduce motion (Settings &#x203A; Accessibility
    /// &#x203A; Visual effects &#x203A; Animation effects). Read afresh each time so the map obeys
    /// the setting the moment it is changed, without the app restarting.
    /// </summary>
    private static bool AnimationsAllowed
    {
        get
        {
            if (_motionProbeFailed) return true;

            try
            {
                _uiSettings ??= new Windows.UI.ViewManagement.UISettings();
                return _uiSettings.AnimationsEnabled;
            }
            catch (Exception)
            {
                // Unreadable accessibility settings are not a reason to strip the app of motion
                // for the rest of the session, but they are a reason to stop asking.
                _motionProbeFailed = true;
                return true;
            }
        }
    }

    // ===================================================================== colour

    /// <summary>
    /// The risk verdict for <paramref name="node"/>, blocking on the assessor if it is not cached.
    /// </summary>
    /// <remarks>
    /// Only ever called for <em>one</em> node the user is pointing at or has selected, where a
    /// single filesystem round trip is imperceptible and a wrong-but-instant answer would not be.
    /// The whole-map path is <see cref="LevelFor"/>, which never blocks.
    /// </remarks>
    private RiskNote RiskFor(DirNode node)
    {
        string path = node.FullPath;

        if (path.Length == 0) return new RiskNote(AggregateLevel, string.Empty, string.Empty);

        if (_riskCache.TryGetValue(path, out RiskNote cached)) return cached;

        RiskNote note = RiskBridge.Assess(path, node.IsDirectory);
        _riskCache[path] = note;
        return note;
    }

    /// <summary>
    /// The risk level to paint <paramref name="node"/> with, or <see cref="UnknownLevel"/> if it is
    /// not known yet — in which case the node is queued for assessment off the UI thread.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Assessing a path is not free and is not pure CPU: it walks the path's ancestors asking the
    /// filesystem about each one, and for a folder it may take a shallow listing. Doing that for
    /// two thousand tiles inline would stall the thread that draws them for as long as the disk
    /// felt like taking — precisely the freeze this control exists to avoid.
    /// </para>
    /// <para>
    /// So the first paint of a level draws unjudged tiles in a neutral tone and the verdicts arrive
    /// in batches from the thread pool, largest tiles first because that is the order they were laid
    /// out in. Every answer is memoised by path, so panning, hovering, filtering, resizing and
    /// switching theme afterwards all repaint from memory and ask nothing.
    /// </para>
    /// </remarks>
    private int LevelFor(DirNode node)
    {
        string path = node.FullPath;

        if (path.Length == 0) return AggregateLevel;
        if (_riskCache.TryGetValue(path, out RiskNote cached)) return cached.Level;

        if (_pendingPaths.Add(path)) _pending.Add(new RiskRequest(path, node.IsDirectory));

        return UnknownLevel;
    }

    /// <summary>Hands this layout's unjudged paths to the thread pool.</summary>
    private void StartRiskWarmup()
    {
        if (_pending.Count == 0) return;

        DispatcherQueue? queue = DispatcherQueue;
        if (queue is null)
        {
            // No dispatcher means no way back to the UI thread, so there is nothing safe to do.
            // The tiles stay neutral, which is honest, rather than blocking to colour them.
            _pending.Clear();
            _pendingPaths.Clear();
            return;
        }

        RiskRequest[] work = [.. _pending];
        int generation = _generation;

        _pending.Clear();
        _pendingPaths.Clear();

        _ = Task.Run(() => AssessAll(work, generation, queue));
    }

    /// <summary>Classifies <paramref name="work"/> on the thread pool, posting verdicts back in batches.</summary>
    private void AssessAll(RiskRequest[] work, int generation, DispatcherQueue queue)
    {
        var batch = new List<KeyValuePair<string, RiskNote>>(RiskBatchSize);

        for (int i = 0; i < work.Length; i++)
        {
            // The layout these paths were collected for may already have been replaced by a drill,
            // a resize or a fresh scan. Stop rather than finish work nobody will look at.
            if (Volatile.Read(ref _generation) != generation) return;

            RiskRequest request = work[i];
            batch.Add(new KeyValuePair<string, RiskNote>(
                request.Path, RiskBridge.Assess(request.Path, request.IsDirectory)));

            if (batch.Count < RiskBatchSize && i < work.Length - 1) continue;

            KeyValuePair<string, RiskNote>[] payload = [.. batch];
            batch.Clear();
            queue.TryEnqueue(() => MergeRisks(payload, generation));
        }
    }

    /// <summary>Folds a batch of verdicts into the cache and recolours the tiles waiting on them.</summary>
    private void MergeRisks(KeyValuePair<string, RiskNote>[] results, int generation)
    {
        // A stale batch may describe paths that a delete-and-rescan has since changed, so it is
        // dropped whole rather than merged into a cache the map is currently trusting.
        if (generation != _generation) return;

        foreach (KeyValuePair<string, RiskNote> result in results) _riskCache[result.Key] = result.Value;

        bool changed = false;

        for (int i = 0; i < _placed.Count; i++)
        {
            PlacedTile tile = _placed[i];

            if (tile.Level != UnknownLevel) continue;
            if (!_riskCache.TryGetValue(tile.Node.FullPath, out RiskNote note)) continue;

            _placed[i] = tile with { Level = note.Level };
            changed = true;
        }

        if (changed) Paint();
    }

    /// <summary>
    /// The brush trio for a tile, cached per (risk, depth) so a 2000-tile map shares a couple of
    /// dozen brushes rather than allocating one per rectangle.
    /// </summary>
    private TileSkin SkinFor(PlacedTile placed)
    {
        var key = new SkinKey(placed.Level, Math.Min(placed.Depth, 5));

        if (_skins.TryGetValue(key, out TileSkin existing)) return existing;

        // Both sentinels — the aggregate and the not-yet-judged — take the neutral tone. Neither
        // has a risk to report, and inventing one for them would be the one thing colour here must
        // never do.
        Color hue = key.Level < RiskBridge.Lowest
            ? _aggregateColor
            : _riskColors[Math.Min(key.Level, RiskBridge.Highest) - 1];

        // Deeper is lighter, so "further in" reads as nearer without touching the hue — the hue is
        // carrying the risk meaning and must not be diluted into a different level's colour.
        Color body = Blend(hue, Colors.White, Math.Min(0.34d, key.Depth * (_isDark ? 0.07d : 0.10d)));

        var fill = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 1),
            GradientStops =
            [
                new GradientStop { Color = Blend(body, Colors.White, 0.07d), Offset = 0 },
                new GradientStop { Color = body, Offset = 0.6 },
                new GradientStop { Color = Shade(body, 0.92d), Offset = 1 },
            ],
        };

        var edge = new SolidColorBrush(_isDark
            ? Blend(body, Colors.White, 0.16d)
            : Shade(body, 0.80d));

        // Per tile, from the fill it actually got: one hardcoded ink cannot stay legible across a
        // ramp that runs from a dark red to a pale green.
        var text = new SolidColorBrush(RelativeLuminance(body) > 0.32d
            ? Color.FromArgb(255, 0x1C, 0x1B, 0x19)
            : Color.FromArgb(255, 0xFF, 0xFF, 0xFF));

        var skin = new TileSkin(fill, edge, text);
        _skins[key] = skin;
        return skin;
    }

    /// <summary>
    /// Reads the five risk colours out of the app resources, falling back to the agreed values.
    /// </summary>
    /// <remarks>
    /// The fallbacks are not belt-and-braces: this control paints before the page it lives on is
    /// loaded, and a missing key would otherwise throw where a slightly-off red would do. The
    /// resource wins whenever it is there, so the design system stays the single source of truth.
    /// </remarks>
    private void ReadPalette()
    {
        for (int level = RiskBridge.Lowest; level <= RiskBridge.Highest; level++)
            _riskColors[level - 1] = Lookup($"Risk{level}Brush", _fallbackRiskColors[level - 1]);

        _aggregateColor = _isDark
            ? Color.FromArgb(255, 0x3A, 0x38, 0x40)
            : Color.FromArgb(255, 0xD8, 0xD5, 0xCC);
    }

    private static Color Lookup(string key, Color fallback)
    {
        try
        {
            if (Application.Current?.Resources is { } resources &&
                resources.TryGetValue(key, out object? value) &&
                value is SolidColorBrush brush)
            {
                return brush.Color;
            }
        }
        catch (Exception)
        {
            // A resource dictionary that is still being merged is not worth crashing a repaint for.
        }

        return fallback;
    }

    /// <summary>
    /// Rebuilds the theme-dependent chrome brushes. Held as fields, not made per hover: the hover
    /// overlay is repositioned on every pointer move and must not allocate.
    /// </summary>
    private void ApplyChromeBrushes()
    {
        Color ink = _isDark
            ? Color.FromArgb(255, 0xF2, 0xF1, 0xEC)
            : Color.FromArgb(255, 0x1C, 0x1B, 0x19);

        // Hover raises the tile rather than moving it: a hairline outline plus a wash of light.
        _hoverStroke = new SolidColorBrush(ink) { Opacity = 0.75 };
        _hoverFill = new SolidColorBrush(Colors.White) { Opacity = _isDark ? 0.12 : 0.20 };
        _selectionStroke = new SolidColorBrush(ink);

        _hoverBorder.BorderBrush = _hoverStroke;
        _hoverBorder.Background = _hoverFill;
        _selectionBorder.BorderBrush = _selectionStroke;

        _emptyLabel.Foreground = new SolidColorBrush(_isDark
            ? Color.FromArgb(255, 0x75, 0x72, 0x6B)
            : Color.FromArgb(255, 0x9A, 0x96, 0x8E));
    }

    private static Color Blend(Color from, Color to, double amount)
    {
        double t = Math.Clamp(amount, 0d, 1d);

        return Color.FromArgb(
            255,
            Channel(from.R + ((to.R - from.R) * t)),
            Channel(from.G + ((to.G - from.G) * t)),
            Channel(from.B + ((to.B - from.B) * t)));
    }

    /// <summary>
    /// Multiplies every channel — below 1 darkens, above 1 lifts. Named <c>Shade</c> rather than
    /// <c>Scale</c> because <see cref="UIElement.Scale"/> already exists on this type and shadowing
    /// a framework member is a trap for whoever reads this next.
    /// </summary>
    private static Color Shade(Color color, double factor) => Color.FromArgb(
        255, Channel(color.R * factor), Channel(color.G * factor), Channel(color.B * factor));

    private static byte Channel(double value) => (byte)Math.Clamp(Math.Round(value), 0d, 255d);

    /// <summary>
    /// WCAG relative luminance, 0..1. Used only to choose between black and white label ink, which
    /// is exactly what it is defined for — the older 0.299/0.587/0.114 weighting works on gamma-
    /// encoded values and picks white over mid-tone greens where black is plainly more readable.
    /// </summary>
    private static double RelativeLuminance(Color color) =>
        (0.2126d * Linear(color.R)) + (0.7152d * Linear(color.G)) + (0.0722d * Linear(color.B));

    private static double Linear(byte channel)
    {
        double value = channel / 255d;
        return value <= 0.03928d ? value / 12.92d : Math.Pow((value + 0.055d) / 1.055d, 2.4d);
    }

    // ===================================================================== value types

    /// <summary>One rectangle that will be drawn, plus what the painter needs to know about it.</summary>
    private readonly record struct PlacedTile(
        DirNode Node,
        double X,
        double Y,
        double Width,
        double Height,
        int Depth,
        double Header,
        bool WillNest,
        bool IsAggregate,
        int Level);

    private readonly record struct SkinKey(int Level, int Depth);

    private readonly record struct TileSkin(Brush Fill, Brush Edge, Brush Text);

    /// <summary>One path waiting on a verdict from the thread pool.</summary>
    private readonly record struct RiskRequest(string Path, bool IsDirectory);
}
