using Ballast.Core.Models;

namespace Ballast.Core.Cleaning;

/// <summary>The user temp folders — usually the single biggest easy win.</summary>
public sealed class TempFilesScanner : DirectoryJunkScanner
{
    public override string Name => "Temporary files";

    protected override JunkCategory Category => JunkCategory.UserTemp;

    protected override IEnumerable<string> Roots
    {
        get
        {
            var temp = Path.GetTempPath();
            yield return temp;

            // %TEMP% normally *is* LocalAppData\Temp, so only add it when it differs.
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var localTemp = Path.Combine(local, "Temp");

            if (!SamePath(localTemp, temp)) yield return localTemp;
        }
    }

    private static bool SamePath(string a, string b)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
