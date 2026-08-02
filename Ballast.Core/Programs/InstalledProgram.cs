using Ballast.Core.Util;

namespace Ballast.Core.Programs;

/// <summary>
/// Which of the three uninstall registries an entry came from. This decides whether removing the
/// program needs elevation, so it must round-trip exactly rather than be inferred from a string.
/// </summary>
public enum ProgramScope
{
    /// <summary>HKCU — installed for the signed-in user only. No elevation needed.</summary>
    CurrentUser,

    /// <summary>HKLM, 64-bit view — installed for every user. Needs administrator rights.</summary>
    AllUsers,

    /// <summary>HKLM, 32-bit (WOW6432Node) view — a 32-bit program for every user. Needs admin.</summary>
    AllUsers32Bit,
}

/// <summary>Presentation facts about a <see cref="ProgramScope"/>.</summary>
public static class ProgramScopeInfo
{
    /// <summary>Short label for a row.</summary>
    public static string DisplayName(this ProgramScope scope) => scope switch
    {
        ProgramScope.CurrentUser   => "Just for you",
        ProgramScope.AllUsers      => "All users",
        ProgramScope.AllUsers32Bit => "All users (32-bit)",
        _ => scope.ToString(),
    };

    /// <summary>One sentence explaining what the scope means for the person reading it.</summary>
    public static string Description(this ProgramScope scope) => scope switch
    {
        ProgramScope.CurrentUser =>
            "Installed under your account only, so removing it does not need administrator rights.",
        ProgramScope.AllUsers =>
            "Installed for everyone who signs in to this PC. Windows will ask for administrator permission.",
        ProgramScope.AllUsers32Bit =>
            "A 32-bit program installed for everyone on this PC. Windows will ask for administrator permission.",
        _ => string.Empty,
    };
}

/// <summary>
/// One entry from the Windows uninstall registry — the same list Add or Remove Programs shows.
/// </summary>
/// <remarks>
/// <para>
/// Purely descriptive. Nothing on this type changes the machine, and in particular nothing here
/// is a path Ballast is allowed to delete: <see cref="InstallLocation"/> exists so the UI can
/// <em>show</em> where a program lives, never so that anything can remove it. Uninstalling is
/// done by handing <see cref="UninstallCommand"/> to <see cref="UninstallLauncher"/>, which
/// starts the vendor's own uninstaller and does nothing else.
/// </para>
/// <para>
/// Almost every field is nullable on purpose. The uninstall registry is written by thousands of
/// different installers and only <c>DisplayName</c> is reliably present; a missing publisher,
/// version, date or size is the normal case, not an error, and the UI has to say "unknown"
/// rather than invent a value.
/// </para>
/// </remarks>
public sealed record InstalledProgram
{
    /// <summary>Shown to the user. The one value Add or Remove Programs insists on.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Vendor, from <c>Publisher</c>. Null when the installer did not record one.</summary>
    public string? Publisher { get; init; }

    /// <summary>Version string as recorded, from <c>DisplayVersion</c>. Not parsed — installers put anything here.</summary>
    public string? Version { get; init; }

    /// <summary>
    /// Install date, from <c>InstallDate</c> (usually <c>yyyyMMdd</c>). Date only: the registry
    /// carries no time, and pretending otherwise would show a fake midnight.
    /// </summary>
    public DateOnly? InstallDate { get; init; }

    /// <summary>
    /// Size on disk in bytes, converted from the <c>EstimatedSize</c> DWORD (which is in
    /// kilobytes). Null means the registry did not say — see <see cref="SizeDisplay"/>.
    /// </summary>
    public long? EstimatedSizeBytes { get; init; }

    /// <summary>Install folder, from <c>InstallLocation</c>. For display only.</summary>
    public string? InstallLocation { get; init; }

    /// <summary>
    /// The vendor's uninstall command line, verbatim from <c>UninstallString</c>. Either
    /// <c>MsiExec.exe /X{GUID}</c> or an arbitrary executable with its own flags.
    /// </summary>
    public string? UninstallCommand { get; init; }

    /// <summary>
    /// The vendor's own silent command line, verbatim from <c>QuietUninstallString</c>, or null.
    /// Never synthesised: a <c>/quiet</c> flag Ballast made up could skip the very prompt that
    /// warns about losing saved data.
    /// </summary>
    public string? QuietUninstallCommand { get; init; }

    /// <summary>
    /// The <c>DisplayIcon</c> value: an executable, .ico or "file,index" reference. Kept for
    /// display purposes; the UI currently draws a neutral glyph instead.
    /// </summary>
    public string? IconPath { get; init; }

    /// <summary>Full path of the key this came from, e.g. <c>HKLM\SOFTWARE\...\Uninstall\{GUID}</c>.</summary>
    public required string RegistryKeyPath { get; init; }

    /// <summary>Which registry the entry was read from.</summary>
    public required ProgramScope Scope { get; init; }

    /// <summary>True when Windows Installer owns this product (<c>WindowsInstaller</c> = 1, or an msiexec command).</summary>
    public bool IsMsi { get; init; }

    /// <summary>The subkey's own name, which is the product code for MSI entries.</summary>
    public string KeyName
    {
        get
        {
            int slash = RegistryKeyPath.LastIndexOf('\\');
            return slash >= 0 && slash < RegistryKeyPath.Length - 1
                ? RegistryKeyPath[(slash + 1)..]
                : RegistryKeyPath;
        }
    }

    /// <summary>
    /// Size for the UI, or an em dash when unknown. Deliberately <em>not</em>
    /// <c>ByteFormatter.Format(0)</c>: that prints "0 KB", and most large programs record no size
    /// at all, so the list would confidently claim they take no space.
    /// </summary>
    public string SizeDisplay => EstimatedSizeBytes is { } bytes and > 0
        ? ByteFormatter.Format(bytes)
        : "—";

    /// <summary>True when Windows will need an elevation prompt to remove this program.</summary>
    public bool RequiresAdmin => Scope != ProgramScope.CurrentUser;

    /// <summary>True when the registry gave us something to run. False means "no uninstaller registered".</summary>
    public bool CanUninstall =>
        !string.IsNullOrWhiteSpace(UninstallCommand) || !string.IsNullOrWhiteSpace(QuietUninstallCommand);

    /// <summary>True when the vendor supplied a silent command line of its own.</summary>
    public bool HasQuietUninstall => !string.IsNullOrWhiteSpace(QuietUninstallCommand);
}
