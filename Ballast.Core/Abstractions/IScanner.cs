using Ballast.Core.Models;

namespace Ballast.Core.Abstractions;

/// <summary>
/// A read-only probe of one junk source. Implementations MUST NOT delete anything.
/// </summary>
public interface IScanner
{
    string Name { get; }

    Task<ScanResult> ScanAsync(
        IProgress<ScanProgress>? progress = null,
        CancellationToken ct = default);
}
