namespace Ballast.Core.Security.Rules;

/// <summary>
/// File names that read as a document and run as a program: <c>invoice.pdf.exe</c>.
/// </summary>
public sealed class DoubleExtensionRule : ISecurityRule
{
    /// <summary>What the name is pretending to be.</summary>
    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
        "jpg", "jpeg", "png", "gif", "bmp", "svg", "mp3", "mp4", "avi", "mkv", "mov",
        "zip", "rar", "7z", "htm", "html",
    };

    /// <summary>What it actually is. <c>.lnk</c> is pointedly absent — see the rationale.</summary>
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "hta", "ps1", "cpl",
    };

    public string RuleId => "BAL-DOUBLE-EXTENSION";

    public string Name => "File names that hide what they really are";

    public string Rationale =>
        "Windows hides known file extensions by default, so a file called invoice.pdf.exe is " +
        "displayed as \"invoice.pdf\" with a PDF-looking name and runs as a program when opened. " +
        "The name exists to be misread. Nothing legitimate is named this way, which is why it is " +
        "High.\n\n" +
        "Deliberately NOT flagged: .lnk. A shortcut to invoice.pdf is genuinely named " +
        "invoice.pdf.lnk by Windows itself, so treating that pair as a disguise would flag ordinary " +
        "shortcuts on every machine. Version numbers are also safe — python3.11.exe and " +
        "app-2.0.4.exe are not matched, because the middle part has to be an actual document, " +
        "image or archive extension rather than merely another dot.";

    public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var findings = new List<SecurityFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in ContextPaths.FileNameTokens(context))
        {
            ct.ThrowIfCancellationRequested();

            var fileName = SafeFileName(candidate.Path);
            if (!IsDisguised(fileName, out var pretend, out var real)) continue;
            if (!seen.Add(candidate.Path)) continue;

            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = $"\"{fileName}\" is named to look like a .{pretend} file",
                Severity = FindingSeverity.High,
                Explanation =
                    $"This file ends in .{pretend}.{real}. Windows hides known extensions, so it " +
                    $"appears in Explorer as a .{pretend} file while actually being a .{real} — " +
                    "something that runs rather than something that opens. That naming is not an " +
                    "accident and no ordinary program ships with a name like it.",
                Evidence = $"{candidate.Path} — {candidate.Origin}.",
                TargetPath = candidate.Path,
                Recommendation =
                    "Do not open it. Ask Windows Security to scan this exact path; deciding whether " +
                    "a file is harmful is its job. Ballast reports the name and changes nothing.",
                CanDisableStartupEntry = candidate.Entry is { IsEnabled: true },
            });
        }

        return Task.FromResult<IReadOnlyList<SecurityFinding>>(findings);
    }

    private static bool IsDisguised(string fileName, out string pretend, out string real)
    {
        pretend = string.Empty;
        real = string.Empty;

        var parts = fileName.Split('.');
        if (parts.Length < 3) return false;

        var last = parts[^1];
        var previous = parts[^2];

        if (!ExecutableExtensions.Contains(last) || !DocumentExtensions.Contains(previous)) return false;

        pretend = previous.ToLowerInvariant();
        real = last.ToLowerInvariant();
        return true;
    }

    private static string SafeFileName(string path)
    {
        try
        {
            return Path.GetFileName(path.Trim('"', '\''));
        }
        catch
        {
            return string.Empty;
        }
    }
}
