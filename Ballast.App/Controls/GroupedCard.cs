using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Ballast.App.Controls;

/// <summary>
/// The standard section container: a labelled group of rows.
///
/// Renders an optional 13px section label, a card holding arbitrary content (surface fill,
/// one hairline border, 8px radius), and an optional 13px footnote underneath. The card is
/// inset 32px from the page edges by the default style; rows go inside as the control's
/// <see cref="ContentControl.Content"/>.
/// </summary>
/// <remarks>
/// The default template lives in <c>Styles/Controls.xaml</c> as an implicit
/// <c>Style TargetType="controls:GroupedCard"</c>. The constructor sets
/// <c>DefaultStyleKey</c> to this type so the lookup resolves out of
/// <c>Application.Resources</c>; there is no <c>Themes/Generic.xaml</c> to keep in sync.
/// </remarks>
public sealed class GroupedCard : ContentControl
{
    /// <summary>Identifies the <see cref="Header"/> dependency property.</summary>
    public static readonly DependencyProperty HeaderProperty =
        DependencyProperty.Register(
            nameof(Header),
            typeof(string),
            typeof(GroupedCard),
            new PropertyMetadata(null, OnLabelChanged));

    /// <summary>Identifies the <see cref="Footer"/> dependency property.</summary>
    public static readonly DependencyProperty FooterProperty =
        DependencyProperty.Register(
            nameof(Footer),
            typeof(string),
            typeof(GroupedCard),
            new PropertyMetadata(null, OnLabelChanged));

    private TextBlock? _headerText;
    private TextBlock? _footerText;

    /// <summary>Points the template lookup at the implicit style in <c>Styles/Controls.xaml</c>.</summary>
    public GroupedCard() => DefaultStyleKey = typeof(GroupedCard);

    /// <summary>
    /// Section label shown above the card, in sentence case. Null or blank collapses it
    /// entirely (no reserved space).
    /// </summary>
    public string? Header
    {
        get => (string?)GetValue(HeaderProperty);
        set => SetValue(HeaderProperty, value);
    }

    /// <summary>
    /// Explanatory footnote shown beneath the card. Null or blank collapses it.
    /// </summary>
    public string? Footer
    {
        get => (string?)GetValue(FooterProperty);
        set => SetValue(FooterProperty, value);
    }

    /// <inheritdoc />
    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();

        _headerText = GetTemplateChild("HeaderText") as TextBlock;
        _footerText = GetTemplateChild("FooterText") as TextBlock;

        UpdateLabels();
    }

    private static void OnLabelChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((GroupedCard)d).UpdateLabels();

    private void UpdateLabels()
    {
        // The label used to be uppercased here. It is shown verbatim now: all-caps is a
        // decoration, and at 13px semibold in secondary ink the label already sits a clear
        // step below the content without shouting.
        Apply(_headerText, Header);
        Apply(_footerText, Footer);

        static void Apply(TextBlock? target, string? text)
        {
            if (target is null) return;

            bool has = !string.IsNullOrWhiteSpace(text);
            target.Text = has ? text! : string.Empty;
            target.Visibility = has ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
