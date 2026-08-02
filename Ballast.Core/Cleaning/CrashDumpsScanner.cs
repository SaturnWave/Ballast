using Ballast.Core.Models;

namespace Ballast.Core.Cleaning;

/// <summary>Crash dumps left behind by apps that stopped working.</summary>
public sealed class CrashDumpsScanner : DirectoryJunkScanner
{
    public override string Name => "Crash reports";

    protected override JunkCategory Category => JunkCategory.CrashDumps;

    protected override IEnumerable<string> Roots
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            yield return Path.Combine(local, "CrashDumps");
        }
    }
}
