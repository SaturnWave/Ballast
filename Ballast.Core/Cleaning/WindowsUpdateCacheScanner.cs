using Ballast.Core.Models;

namespace Ballast.Core.Cleaning;

/// <summary>
/// Update payloads Windows already applied. Deliberately conservative: an update can sit
/// staged for days before it installs, so only clearly stale downloads are offered.
/// </summary>
public sealed class WindowsUpdateCacheScanner : DirectoryJunkScanner
{
    public override string Name => "Windows Update cache";

    protected override JunkCategory Category => JunkCategory.WindowsUpdateCache;

    protected override bool RequiresAdmin => true;

    protected override TimeSpan MinimumAge => TimeSpan.FromDays(7);

    protected override IEnumerable<string> Roots
    {
        get
        {
            yield return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "SoftwareDistribution", "Download");
        }
    }
}
