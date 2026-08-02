using System.Security.Principal;

namespace Ballast.Core.Util;

public static class Elevation
{
    private static readonly Lazy<bool> _isAdmin = new(() =>
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    });

    /// <summary>True when the current process can write to machine-wide locations.</summary>
    public static bool IsElevated => _isAdmin.Value;
}
