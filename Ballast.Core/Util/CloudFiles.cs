namespace Ballast.Core.Util;

/// <summary>
/// Guards against touching cloud-backed placeholder files (OneDrive Files On-Demand,
/// Google Drive for desktop, Dropbox Smart Sync, iCloud Drive).
///
/// <para>
/// Two independent reasons this matters:
/// </para>
/// <list type="number">
/// <item><b>Correctness.</b> A dehydrated placeholder occupies almost no local disk. Counting its
/// logical length as "space used" would inflate every total we show — a 500 GB cloud folder that
/// takes 2 MB on disk would read as 500 GB.</item>
/// <item><b>Cost.</b> Opening one forces the sync client to download it. Walking a cloud folder
/// could silently pull down hundreds of gigabytes over a metered connection.</item>
/// </list>
///
/// <para>
/// Enumerating metadata alone does not hydrate a file, so these attributes are used to *exclude*
/// placeholders from results rather than to avoid reading them.
/// </para>
/// </summary>
public static class CloudFiles
{
    /// <summary>
    /// <c>FILE_ATTRIBUTE_RECALL_ON_OPEN</c> — opening the file triggers a fetch.
    /// Not exposed by the <see cref="FileAttributes"/> enum, so the Win32 bit is used directly.
    /// </summary>
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;

    /// <summary>
    /// <c>FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS</c> — reading content triggers a fetch. This is the
    /// attribute OneDrive Files On-Demand and Google Drive for desktop actually set.
    /// Not exposed by the <see cref="FileAttributes"/> enum either.
    /// </summary>
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

    /// <summary>
    /// Attributes marking an entry as not really present on this disk.
    ///
    /// <list type="bullet">
    /// <item><see cref="FileAttributes.Offline"/> — content is not local.</item>
    /// <item><c>RecallOnOpen</c> / <c>RecallOnDataAccess</c> — touching it downloads it.</item>
    /// <item><see cref="FileAttributes.ReparsePoint"/> — junctions and symlinks, which would also
    /// let a walk escape its root or loop forever.</item>
    /// </list>
    /// </summary>
    public const FileAttributes PlaceholderAttributes =
        FileAttributes.Offline |
        RecallOnOpen |
        RecallOnDataAccess |
        FileAttributes.ReparsePoint;

    /// <summary>True when the entry is a link or a not-yet-downloaded cloud placeholder.</summary>
    public static bool IsPlaceholder(FileAttributes attributes) =>
        (attributes & PlaceholderAttributes) != 0;

    public static bool IsPlaceholder(FileSystemInfo info)
    {
        try { return IsPlaceholder(info.Attributes); }
        catch { return true; } // unreadable attributes: treat as untouchable
    }

    /// <summary>
    /// Shared enumeration settings: tolerate inaccessible paths, stay in the current directory,
    /// and never surface placeholders or links.
    /// </summary>
    public static EnumerationOptions ShallowEnumeration() => new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        AttributesToSkip = PlaceholderAttributes,
    };
}
