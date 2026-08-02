using System.Collections;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Ballast.App.Converters;

/// <summary>
/// Shows an element only when a count (or a collection) is non-empty. Accepts an
/// <see cref="int"/>, a <see cref="long"/>, or anything implementing <see cref="ICollection"/>.
/// Pass <c>Invert</c> to show the empty-state element instead.
/// </summary>
public sealed class CountToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        bool any = value switch
        {
            int i => i > 0,
            long l => l > 0,
            double d => d > 0,
            ICollection c => c.Count > 0,
            IEnumerable e => e.GetEnumerator().MoveNext(),
            _ => false,
        };

        if (BoolToVisibilityConverter.IsInverted(parameter)) any = !any;
        return any ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        throw new NotSupportedException("Counts are display-only.");
}
