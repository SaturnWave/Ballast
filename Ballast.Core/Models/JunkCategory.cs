namespace Ballast.Core.Models;

/// <summary>Logical grouping a <see cref="CleanupItem"/> belongs to, shown as a section in the UI.</summary>
public enum JunkCategory
{
    UserTemp,
    WindowsTemp,
    BrowserCache,
    ThumbnailCache,
    WindowsUpdateCache,
    RecycleBin,
    CrashDumps,
}

public static class JunkCategoryInfo
{
    public static string DisplayName(this JunkCategory c) => c switch
    {
        JunkCategory.UserTemp           => "Temporary Files",
        JunkCategory.WindowsTemp        => "System Temp",
        JunkCategory.BrowserCache       => "Browser Caches",
        JunkCategory.ThumbnailCache     => "Thumbnail Cache",
        JunkCategory.WindowsUpdateCache => "Windows Update Cache",
        JunkCategory.RecycleBin         => "Recycle Bin",
        JunkCategory.CrashDumps         => "Crash Reports",
        _ => c.ToString(),
    };

    public static string Description(this JunkCategory c) => c switch
    {
        JunkCategory.UserTemp           => "Leftover files apps wrote to your temp folder and never cleaned up.",
        JunkCategory.WindowsTemp        => "Windows' own temp folder. Requires administrator rights.",
        JunkCategory.BrowserCache       => "Cached images and files from Edge, Chrome and Firefox. History and passwords are never touched.",
        JunkCategory.ThumbnailCache     => "Explorer's thumbnail previews. Windows rebuilds these automatically.",
        JunkCategory.WindowsUpdateCache => "Installers Windows Update already applied. Requires administrator rights.",
        JunkCategory.RecycleBin         => "Files you already deleted.",
        JunkCategory.CrashDumps         => "Error reports and crash dumps from apps that stopped working.",
        _ => string.Empty,
    };

    /// <summary>Glyph from the Segoe Fluent Icons font.</summary>
    public static string Glyph(this JunkCategory c) => c switch
    {
        JunkCategory.UserTemp           => "\uE7C3",
        JunkCategory.WindowsTemp        => "\uE770",
        JunkCategory.BrowserCache       => "\uE774",
        JunkCategory.ThumbnailCache     => "\uEB9F",
        JunkCategory.WindowsUpdateCache => "\uE895",
        JunkCategory.RecycleBin         => "\uE74D",
        JunkCategory.CrashDumps         => "\uE7BA",
        _ => "\uE7C3",
    };
}
