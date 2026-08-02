using Ballast.Core.Util;
using Microsoft.UI.Xaml.Data;

namespace Ballast.App.Converters;

/// <summary>
/// Formats a byte count for display. Pure delegation to <see cref="ByteFormatter.Format(long)"/>
/// so the UI and the Core agree on units (decimal, iOS style) in exactly one place.
/// </summary>
public sealed class BytesToStringConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, string language) =>
        ByteFormatter.Format(ToInt64(value));

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException("Byte sizes are display-only.");

    private static long ToInt64(object? value) => value switch
    {
        long l => l,
        int i => i,
        double d => (long)d,
        ulong u => (long)Math.Min(u, long.MaxValue),
        string s when long.TryParse(s, out long parsed) => parsed,
        _ => 0L,
    };
}
