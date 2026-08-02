using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace Ballast.App.Converters;

/// <summary>
/// <c>true</c> to <see cref="Visibility.Visible"/>. Pass <c>Invert</c> as the converter
/// parameter to flip the mapping.
/// </summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        bool flag = value is bool b && b;
        if (IsInverted(parameter)) flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        bool visible = value is Visibility v && v == Visibility.Visible;
        return IsInverted(parameter) ? !visible : visible;
    }

    internal static bool IsInverted(object? parameter) =>
        parameter is string s &&
        (s.Equals("Invert", StringComparison.OrdinalIgnoreCase) ||
         s.Equals("Inverse", StringComparison.OrdinalIgnoreCase) ||
         s.Equals("Not", StringComparison.OrdinalIgnoreCase));
}
