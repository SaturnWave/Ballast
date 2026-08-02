using Ballast.Core.Models;

namespace Ballast.Core.Cleaning;

/// <summary>C:\Windows\Temp. Needs elevation to clear.</summary>
public sealed class WindowsTempScanner : DirectoryJunkScanner
{
    public override string Name => "System temp";

    protected override JunkCategory Category => JunkCategory.WindowsTemp;

    protected override bool RequiresAdmin => true;

    protected override IEnumerable<string> Roots
    {
        get
        {
            yield return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
        }
    }
}
