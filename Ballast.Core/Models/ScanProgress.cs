namespace Ballast.Core.Models;

/// <summary>Progress ticket reported while a scan runs. Cheap to allocate; sent often.</summary>
public readonly record struct ScanProgress(
    string CurrentPath,
    long ItemsFound,
    long BytesFound,
    double? Fraction = null);
