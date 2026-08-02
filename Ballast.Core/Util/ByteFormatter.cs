namespace Ballast.Core.Util;

public static class ByteFormatter
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB", "PB"];

    /// <summary>Formats bytes the way macOS/iOS do: decimal units, at most one decimal place.</summary>
    public static string Format(long bytes)
    {
        if (bytes <= 0) return "0 KB";

        double value = bytes;
        int unit = 0;
        while (value >= 1000 && unit < Units.Length - 1)
        {
            value /= 1000;
            unit++;
        }

        // Whole numbers for bytes/KB, one decimal from MB up.
        return unit <= 1
            ? $"{Math.Round(value)} {Units[unit]}"
            : $"{value:0.#} {Units[unit]}";
    }
}
