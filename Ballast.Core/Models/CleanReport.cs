namespace Ballast.Core.Models;

/// <summary>What actually happened during a delete pass.</summary>
public sealed class CleanReport
{
    public long BytesFreed { get; init; }
    public int ItemsDeleted { get; init; }
    public IReadOnlyList<CleanFailure> Failures { get; init; } = [];
}

public sealed record CleanFailure(string Path, string Reason);
