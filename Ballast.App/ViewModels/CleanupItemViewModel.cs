using Ballast.Core.Models;
using Ballast.Core.Util;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Ballast.App.ViewModels;

/// <summary>
/// One deletable row inside a category. Wraps an immutable <see cref="CleanupItem"/> and adds the
/// only mutable bit the UI needs: whether the user wants it included.
/// </summary>
public sealed partial class CleanupItemViewModel : ObservableObject
{
    private readonly JunkCategoryViewModel? _parent;

    /// <summary>Creates a row for <paramref name="item"/>, reporting selection changes to its group.</summary>
    public CleanupItemViewModel(CleanupItem item, JunkCategoryViewModel? parent = null)
    {
        Item = item;

        // Initializer moved here from the field: a partial property cannot carry one. Assigned
        // before _parent so construction does not report a selection change to the group.
        IsSelected = true;

        _parent = parent;
    }

    /// <summary>The underlying scan result. Never mutated.</summary>
    public CleanupItem Item { get; }

    /// <summary>Included in the next clean pass.</summary>
    [ObservableProperty]
    private bool _isSelected;

    /// <summary>File or folder name, or the scanner-supplied description.</summary>
    public string DisplayName => Item.DisplayName;

    /// <summary>Full path, shown as secondary text.</summary>
    public string Path => Item.Path;

    /// <summary>Bytes this row would reclaim.</summary>
    public long SizeBytes => Item.SizeBytes;

    /// <summary>Formatted size for the trailing label.</summary>
    public string SizeDisplay => ByteFormatter.Format(Item.SizeBytes);

    /// <summary>True when this row needs an elevated process to be removed.</summary>
    public bool RequiresAdmin => Item.RequiresAdmin;

    /// <summary>
    /// Segoe Fluent Icons glyph: FolderHorizontal for directories, Page for files.
    /// Built from code points rather than pasted private-use characters so the source file
    /// stays plain ASCII.
    /// </summary>
    public string Glyph => Item.IsDirectory ? Glyphs.Folder : Glyphs.Page;

    partial void OnIsSelectedChanged(bool value) => _parent?.OnChildSelectionChanged();
}

/// <summary>Segoe Fluent Icons code points used by the view models.</summary>
internal static class Glyphs
{
    /// <summary>FolderHorizontal.</summary>
    public static string Folder { get; } = char.ConvertFromUtf32(0xF12B);

    /// <summary>Page.</summary>
    public static string Page { get; } = char.ConvertFromUtf32(0xE7C3);

    /// <summary>Disc / drive.</summary>
    public static string Drive { get; } = char.ConvertFromUtf32(0xEDA2);

    /// <summary>OpenLocal (a folder tile).</summary>
    public static string FolderTile { get; } = char.ConvertFromUtf32(0xE838);

    /// <summary>Rocket-ish "startup" glyph (Streaming).</summary>
    public static string Startup { get; } = char.ConvertFromUtf32(0xE945);

    /// <summary>Chevron down.</summary>
    public static string ChevronDown { get; } = char.ConvertFromUtf32(0xE70D);

    /// <summary>Chevron up.</summary>
    public static string ChevronUp { get; } = char.ConvertFromUtf32(0xE70E);
}
