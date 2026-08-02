namespace Ballast.Core.Security.Rules;

/// <summary>
/// Reads <c>%WINDIR%\System32\drivers\etc\hosts</c> and reports name overrides that are not
/// simple blocking. Read-only, like everything else in this namespace.
/// </summary>
public sealed class HostsFileRule : ISecurityRule
{
    /// <summary>Stop reading after this many lines. Ad-blocking hosts files run to six figures.</summary>
    private const int MaxLines = 50_000;

    /// <summary>How many entries to quote in the Evidence line before summarising the rest.</summary>
    private const int MaxExamples = 5;

    /// <summary>
    /// Domain labels belonging to security vendors and to Windows' own update and protection
    /// services. Matched as whole labels, never as substrings: "avg" as a substring would match
    /// "avgle.com", and a finding that misreads a blocked website as a blocked antivirus is
    /// exactly the sort of false alarm that gets this page ignored.
    /// </summary>
    private static readonly HashSet<string> SensitiveLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "avast", "avg", "avira", "bitdefender", "eset", "nod32", "kaspersky", "mcafee", "norton",
        "symantec", "sophos", "trendmicro", "malwarebytes", "virustotal", "clamav", "f-secure",
        "drweb", "comodo", "pandasecurity", "webroot", "emsisoft", "gdata", "sucuri", "quickheal",
        "adaware", "spybot", "hitmanpro", "defender", "windowsdefender", "wdcp", "wdcpalt",
        "definitionupdates", "smartscreen", "windowsupdate", "wustat", "msftncsi", "msftconnecttest",
    };

    private readonly string _hostsFilePath;

    /// <param name="hostsFilePath">
    /// Overrides the real hosts file. Exists so the rule can be tested against known content:
    /// a rule whose test result depends on the hosts file of whichever machine runs the suite
    /// is not testing the rule.
    /// </param>
    public HostsFileRule(string? hostsFilePath = null) =>
        _hostsFilePath = hostsFilePath ?? DefaultHostsPath();

    public string RuleId => "BAL-HOSTS-TAMPERED";

    public string Name => "Changes to the hosts file";

    public string Rationale =>
        "The hosts file overrides DNS for the whole PC. An entry there decides where a name points " +
        "before any browser, updater or security product gets a say, which makes it a quiet way to send " +
        "traffic somewhere else, or to cut a machine off from its own updates and protection.\n\n" +
        "It is Medium, never High, because people edit this file deliberately all the time: " +
        "developers point a production hostname at a local server, and millions of PCs run " +
        "ad-blocking hosts files with tens of thousands of entries in them. The wording therefore " +
        "says what was found and lets the reader recognise their own work.\n\n" +
        "Deliberately NOT flagged: comments, blank lines, and the ordinary blocking form where a " +
        "name is sent to a loopback address — that is what every ad-blocking list does, and " +
        "reporting it would bury the page in noise. Blocking is only reported when the name " +
        "belongs to a security vendor or to Windows Update, because that specific combination is " +
        "worth knowing about even when a person did it on purpose. Findings are aggregated: a " +
        "hosts file with 60,000 entries produces at most one finding, not 60,000.";

    public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(
        SecurityScanContext context,
        CancellationToken ct = default)
    {
        var redirects = new List<string>();
        var blocked = new List<string>();
        var redirectCount = 0;
        var blockedCount = 0;

        foreach (var line in ReadLines(ct))
        {
            var text = line;

            var comment = text.IndexOf('#');
            if (comment >= 0) text = text[..comment];

            text = text.Trim();
            if (text.Length == 0) continue;

            var parts = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var address = parts[0];
            var loopback = IsLoopbackOrNull(address);

            foreach (var host in parts.Skip(1))
            {
                if (!loopback)
                {
                    redirectCount++;
                    if (redirects.Count < MaxExamples) redirects.Add($"{host} \u2192 {address}");
                }
                else if (IsSensitive(host))
                {
                    blockedCount++;
                    if (blocked.Count < MaxExamples) blocked.Add($"{host} \u2192 {address}");
                }
            }
        }

        var findings = new List<SecurityFinding>();

        if (redirectCount > 0)
        {
            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = "The hosts file sends some names to a specific address",
                Severity = FindingSeverity.Medium,
                Explanation =
                    "The hosts file on this PC redirects one or more names to a particular address " +
                    "rather than letting normal name lookup answer. Everything on this PC will " +
                    "follow that override, browsers included. Developers and IT departments do this " +
                    "on purpose — pointing a live hostname at a test server is routine — so the " +
                    "question is simply whether these entries are ones you or your workplace put " +
                    "there.",
                Evidence = Summarise(redirects, redirectCount, "redirection") + $" File: {_hostsFilePath}.",
                TargetPath = _hostsFilePath,
                Recommendation =
                    "Open the file in Notepad and read it. Ballast does not edit it: changing name " +
                    "resolution for the whole PC is not something an automated cleanup should do, " +
                    "and one of these entries may well be yours.",
            });
        }

        if (blockedCount > 0)
        {
            findings.Add(new SecurityFinding
            {
                RuleId = RuleId,
                Title = "The hosts file blocks security or update addresses",
                Severity = FindingSeverity.Medium,
                Explanation =
                    "The hosts file sends the names of security software vendors or Windows update " +
                    "services to a dead address, which stops this PC reaching them. Some people do this " +
                    "deliberately to hold back updates or block telemetry. It is also the first " +
                    "thing done by anything that would rather not be found, so it is worth knowing " +
                    "which of the two this is.",
                Evidence = Summarise(blocked, blockedCount, "blocked name") + $" File: {_hostsFilePath}.",
                TargetPath = _hostsFilePath,
                Recommendation =
                    "If you or a tool you installed added these, nothing needs doing. If not, " +
                    "removing the lines restores normal access — edit the file yourself in Notepad " +
                    "as an administrator. Ballast reports it and changes nothing.",
            });
        }

        return Task.FromResult<IReadOnlyList<SecurityFinding>>(findings);
    }

    private IEnumerable<string> ReadLines(CancellationToken ct)
    {
        List<string> lines;

        try
        {
            if (!File.Exists(_hostsFilePath)) return [];

            lines = new List<string>();
            foreach (var line in File.ReadLines(_hostsFilePath))
            {
                ct.ThrowIfCancellationRequested();
                lines.Add(line);
                if (lines.Count >= MaxLines) break;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Unreadable, locked, or a path we are not allowed to touch. Cannot tell means silent.
            return [];
        }

        return lines;
    }

    private static string Summarise(List<string> examples, int total, string noun)
    {
        var shown = string.Join("; ", examples);
        var suffix = total > examples.Count
            ? $" and {total - examples.Count} more (of {total} {noun} entries in total)"
            : total == 1 ? string.Empty : $" ({total} {noun} entries in total)";

        return shown + suffix + ".";
    }

    /// <summary>
    /// True for the addresses that mean "nowhere": loopback and the unspecified address, which is
    /// what every blocking list uses.
    /// </summary>
    private static bool IsLoopbackOrNull(string address)
    {
        if (address.StartsWith("127.", StringComparison.Ordinal)) return true;
        if (address.StartsWith("0.0.0.0", StringComparison.Ordinal)) return true;

        var trimmed = address.Trim('[', ']');
        return trimmed is "::1" or "::" or "0:0:0:0:0:0:0:0" or "0:0:0:0:0:0:0:1";
    }

    private static bool IsSensitive(string hostName)
    {
        foreach (var label in hostName.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (SensitiveLabels.Contains(label)) return true;
        }

        return false;
    }

    private static string DefaultHostsPath()
    {
        try
        {
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            return string.IsNullOrEmpty(system)
                ? @"C:\Windows\System32\drivers\etc\hosts"
                : Path.Combine(system, "drivers", "etc", "hosts");
        }
        catch
        {
            return @"C:\Windows\System32\drivers\etc\hosts";
        }
    }
}
