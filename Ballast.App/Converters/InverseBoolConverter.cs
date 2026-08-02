using Microsoft.UI.Xaml.Data;

namespace Ballast.App.Converters;

/// <summary>
/// Negates a boolean, for "enabled while not scanning" style bindings against a raw
/// <c>IsBusy</c> flag. The pages here mostly bind the view models' own <c>IsIdle</c> instead,
/// so this is the escape hatch for a flag that has no inverse of its own.
/// </summary>
public sealed class InverseBoolConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is not bool b || !b;

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        value is not bool b || !b;
}
