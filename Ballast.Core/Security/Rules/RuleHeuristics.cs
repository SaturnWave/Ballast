using Ballast.Core.Startup;

namespace Ballast.Core.Security.Rules;

/// <summary>
/// Structural facts about a path. Every method here is <em>lexical</em>: it reasons about the
/// shape of the string and never touches the disk.
/// </summary>
/// <remarks>
/// <para>
/// That is a deliberate constraint, for three reasons. Rules must be cheap — the audit already
/// pays eight seconds for scheduled tasks and must not add a stat call per rule per entry.
/// A missing file must not silently change a verdict: an auto-start entry pointing at
/// <c>%TEMP%\thing.exe</c> is worth reporting whether or not the file is still there. And a
/// heuristic that consults the machine cannot be tested against the machine, which is exactly
/// what these rules need to be.
/// </para>
/// <para>
/// The one concession to the real machine is <see cref="IsUnderWindowsFolder"/>, which checks the
/// live <c>%WINDIR%</c> in addition to the structural test, because getting that one wrong in the
/// permissive direction would blunt the impersonation rule.
/// </para>
/// </remarks>
internal static class PathFacts
{
    private static readonly char[] Separators = ['\\', '/'];

    /// <summary>Folder names that mean "scratch space" wherever they appear in a path.</summary>
    private static readonly string[] TempSegments = ["temp", "tmp", "%temp%", "%tmp%"];

    /// <summary>Recycle Bin container names, current and legacy.</summary>
    private static readonly string[] RecycleSegments = ["$recycle.bin", "recycler", "$recycle"];

    private static readonly string WindowsFolder = SafeFolder(Environment.SpecialFolder.Windows);

    internal static string[] Segments(string path) =>
        path.Split(Separators, StringSplitOptions.RemoveEmptyEntries);

    /// <summary>True for <c>C:\...</c>. Deliberately not <c>Path.IsPathRooted</c>, which also accepts <c>\foo</c>.</summary>
    internal static bool IsDriveRooted(string? path) =>
        path is { Length: >= 3 } p && char.IsLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/');

    /// <summary>True for <c>\\server\share\...</c>.</summary>
    internal static bool IsUnc(string? path) =>
        path is { Length: >= 3 } p && (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/');

    /// <summary>
    /// True when the path says where the file is. A bare <c>svchost.exe</c> resolved through
    /// <c>PATH</c> does not, and a rule that cannot locate a file must not judge it.
    /// </summary>
    internal static bool IsLocatable(string? path) => IsDriveRooted(path) || IsUnc(path);

    /// <summary>
    /// True for a path that begins with an environment variable reference, such as
    /// <c>%windir%\system32\thing.dll</c>.
    /// </summary>
    /// <remarks>
    /// Registry Run values and scheduled-task actions store paths this way constantly — two stock
    /// Windows tasks on the machine this was measured against do — and to
    /// <see cref="IsLocatable"/> they look exactly like an unresolvable bare command name.
    /// </remarks>
    internal static bool IsEnvironmentRooted(string? path) =>
        path is { Length: > 2 } p && p[0] == '%' && p.IndexOf('%', 1) > 1;

    /// <summary>
    /// True when a file could be found from this string — either because it is already a full path
    /// or because the environment will make it one. This is the test to use before asking for a
    /// signature; <see cref="AuthenticodeVerifier"/> expands the variables itself.
    /// </summary>
    internal static bool CanLocate(string? path) => IsLocatable(path) || IsEnvironmentRooted(path);

    /// <summary>True when any <c>\</c>-delimited segment equals one of <paramref name="names"/>.</summary>
    internal static bool HasSegment(string path, params string[] names)
    {
        foreach (var segment in Segments(path))
        {
            foreach (var name in names)
            {
                if (segment.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }

        return false;
    }

    /// <summary>Scratch space: a <c>Temp</c>/<c>tmp</c> folder anywhere, or the Recycle Bin.</summary>
    internal static bool IsTempLike(string path) =>
        HasSegment(path, TempSegments) || HasSegment(path, RecycleSegments);

    internal static bool IsRecycleBin(string path) => HasSegment(path, RecycleSegments);

    internal static bool IsDownloads(string path) => HasSegment(path, "downloads");

    /// <summary>
    /// True when the path sits under the Windows folder — including <c>WinSxS</c> and
    /// <c>Windows.old</c>, which hold genuine copies of system binaries and would otherwise be a
    /// steady source of false positives after a feature update.
    /// </summary>
    internal static bool IsUnderWindowsFolder(string path)
    {
        // %windir% and %systemroot% name the Windows folder by definition on every Windows
        // machine, so recognising them is a structural fact and not an expansion against this
        // machine. Stock scheduled tasks write their paths this way, and treating them as
        // unknown locations put a Medium finding on two of Windows' own tasks.
        if (path.StartsWith("%windir%", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("%systemroot%", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (WindowsFolder.Length > 0 &&
            path.StartsWith(WindowsFolder + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Structural fallback: the first segment under a drive root. This is what stops
        // C:\Users\bob\Windows\svchost.exe from passing as a system location.
        var segments = Segments(path);
        return segments.Length >= 2
            && segments[0].EndsWith(':')
            && (segments[1].Equals("Windows", StringComparison.OrdinalIgnoreCase)
                || segments[1].Equals("Windows.old", StringComparison.OrdinalIgnoreCase)
                || segments[1].Equals("WinNT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True for the locations Windows will not let a standard user write to: the Windows folder
    /// and both Program Files trees, in drive-rooted or environment-variable form.
    /// </summary>
    /// <remarks>
    /// This is an argument about the write barrier, not about trust. Getting a file into one of
    /// these already requires administrator rights, so a helper binary pointed at a script living
    /// there was put there by an installer. It matters because <c>.bat</c>, <c>.cmd</c> and in
    /// practice <c>.ps1</c> cannot carry an Authenticode signature, so a signature check can never
    /// clear them — <c>cmd.exe /c "C:\Program Files\nodejs\npm.cmd"</c> would otherwise be a
    /// permanent Medium finding on every machine with Node on it. Persistence that does not
    /// already have administrator rights has to live somewhere user-writable, which is exactly
    /// what this leaves in scope.
    /// </remarks>
    internal static bool RequiresAdminToWrite(string path)
    {
        if (IsTempLike(path)) return false;
        if (IsUnderWindowsFolder(path)) return true;

        if (path.StartsWith("%programfiles", StringComparison.OrdinalIgnoreCase)) return true;

        var segments = Segments(path);
        return segments.Length >= 2
            && segments[0].EndsWith(':')
            && (segments[1].Equals("Program Files", StringComparison.OrdinalIgnoreCase)
                || segments[1].Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Locations where an auto-start program is genuinely out of place, as opposed to merely
    /// user-owned. <c>AppData</c> is <em>not</em> here: a great deal of ordinary software
    /// (editors, chat clients, browsers) installs per-user under <c>AppData\Local\Programs</c>,
    /// and treating that as anomalous would flag half a normal machine.
    /// </summary>
    internal static bool IsOutOfPlaceLocation(string path)
    {
        if (IsTempLike(path) || IsDownloads(path) || IsUnc(path)) return true;

        var segments = Segments(path);

        // C:\Users\Public\... — writable by every account on the PC.
        if (segments.Length >= 3
            && segments[0].EndsWith(':')
            && segments[1].Equals("Users", StringComparison.OrdinalIgnoreCase)
            && segments[2].Equals("Public", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // C:\something.exe — nothing installs to the bare root of a drive.
        return segments.Length == 2 && segments[0].EndsWith(':');
    }

    /// <summary>A human label for where a file lives, for the Evidence line.</summary>
    internal static string DescribeLocation(string path)
    {
        if (IsRecycleBin(path)) return "the Recycle Bin";
        if (IsTempLike(path)) return "a temporary folder";
        if (IsDownloads(path)) return "a Downloads folder";
        if (IsUnc(path)) return "a network location";
        return "an unusual location for a program that starts automatically";
    }

    /// <summary>
    /// Strips the <c>,0</c> icon index from a <c>DisplayIcon</c> value. The registry stores
    /// <c>C:\App\app.exe,0</c> and treating that as a file name would break every extension check.
    /// </summary>
    internal static string TrimIconIndex(string value)
    {
        var comma = value.LastIndexOf(',');
        if (comma <= 0) return value;

        var tail = value[(comma + 1)..].Trim();
        return tail.Length > 0 && tail.All(c => char.IsDigit(c) || c == '-') ? value[..comma].Trim() : value;
    }

    private static string SafeFolder(Environment.SpecialFolder folder)
    {
        try
        {
            return Environment.GetFolderPath(folder).TrimEnd('\\');
        }
        catch
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// Structural facts about a command line. Also entirely lexical — in particular nothing here
/// expands environment variables, because expansion resolves against the running machine and
/// would make the same command mean different things in a test and in production.
/// </summary>
internal static class CommandFacts
{
    /// <summary>Extensions that make a token a runnable thing rather than data.</summary>
    private static readonly string[] ExecutableExtensions =
        [".exe", ".com", ".scr", ".bat", ".cmd", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".msi", ".cpl"];

    /// <summary>Things a living-off-the-land binary can be pointed at.</summary>
    private static readonly string[] PayloadExtensions =
        [".dll", ".ocx", ".sct", ".xsl", ".xml", ".inf", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".exe", ".msi", ".scr", ".sys"];

    /// <summary>
    /// Splits a command line the way Windows does for the purposes of reading it: double quotes
    /// group, whitespace separates. Not a faithful CommandLineToArgvW — it does not need to be,
    /// because every rule that uses it only inspects tokens, never re-executes them.
    /// </summary>
    internal static IReadOnlyList<string> Tokenise(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return [];

        var tokens = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;

        foreach (var c in command)
        {
            if (c == '"')
            {
                quoted = !quoted;
                continue;
            }

            if (!quoted && char.IsWhiteSpace(c))
            {
                if (current.Length > 0)
                {
                    tokens.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(c);
        }

        if (current.Length > 0) tokens.Add(current.ToString());
        return tokens;
    }

    /// <summary>
    /// The program a command line runs, without asking the disk whether it exists.
    /// </summary>
    /// <remarks>
    /// Quoted commands are easy. Unquoted ones are not, because
    /// <c>C:\Users\John Doe\app.exe -q</c> and <c>C:\Windows\notepad.exe file.txt</c> have the
    /// same shape. The tie is broken the same way <c>UninstallLauncher</c> breaks it — the
    /// longest prefix ending in an executable extension wins — falling back to the first token
    /// when there is no extension at all (<c>powershell -enc ...</c>).
    /// </remarks>
    internal static string? ExecutableFromCommand(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;

        var text = command.Trim();

        if (text[0] == '"')
        {
            var close = text.IndexOf('"', 1);
            var inner = (close > 1 ? text[1..close] : text[1..]).Trim();
            return inner.Length == 0 ? null : inner;
        }

        // Walk the token boundaries left to right and take the first prefix that ends in an
        // executable extension. Searching per-extension instead would read
        // "C:\tools\run.cmd C:\x\a.exe" as one long program name, because .exe is looked for
        // before .cmd — and the program would come out as the argument rather than the command.
        for (var i = 0; i <= text.Length; i++)
        {
            if (i != text.Length && !char.IsWhiteSpace(text[i])) continue;

            foreach (var extension in ExecutableExtensions)
            {
                if (i > extension.Length && text.AsSpan(0, i).EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                    return text[..i].Trim();
            }
        }

        var first = Tokenise(text).FirstOrDefault()?.TrimEnd(',');
        return string.IsNullOrWhiteSpace(first) ? null : first;
    }

    /// <summary>The file name of the program a command runs, lower-cased, or an empty string.</summary>
    internal static string ProgramFileName(string? command)
    {
        var exe = ExecutableFromCommand(command);
        if (string.IsNullOrWhiteSpace(exe)) return string.Empty;

        try
        {
            return Path.GetFileName(exe.Trim('"', '\'')).ToLowerInvariant();
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>Everything after the program itself.</summary>
    internal static IReadOnlyList<string> Arguments(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return [];

        var text = command.Trim();

        if (text[0] == '"')
        {
            var close = text.IndexOf('"', 1);
            return close < 0 ? [] : Tokenise(text[(close + 1)..]);
        }

        // ExecutableFromCommand returns a prefix of the unquoted command, so the remainder is
        // exactly the argument list — splitting on whitespace first would lose a spaced path.
        var exe = ExecutableFromCommand(text);
        return exe is { Length: > 0 } && text.StartsWith(exe, StringComparison.Ordinal)
            ? Tokenise(text[exe.Length..])
            : Tokenise(text).Skip(1).ToArray();
    }

    /// <summary>
    /// Drops a switch prefix so the value can be judged on its own: <c>/i:http://host/x</c>
    /// becomes <c>http://host/x</c>. Only short prefixes are stripped, so <c>C:\path</c> survives.
    /// </summary>
    internal static string StripSwitchPrefix(string token)
    {
        if (token.Length < 2 || (token[0] != '/' && token[0] != '-')) return token;

        var colon = token.IndexOf(':');
        return colon is > 0 and <= 4 ? token[(colon + 1)..] : token;
    }

    /// <summary>True when a token names something that is not on this PC, or is a script URI.</summary>
    internal static bool IsRemoteReference(string token)
    {
        var value = StripSwitchPrefix(token.Trim('"', '\'')).TrimStart();

        return value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase)
            || PathFacts.IsUnc(value);
    }

    /// <summary>The first argument that names a file a helper binary could be told to run.</summary>
    internal static string? FirstPayloadReference(IReadOnlyList<string> arguments)
    {
        foreach (var raw in arguments)
        {
            var token = StripSwitchPrefix(raw.Trim('"', '\'')).TrimEnd(',');
            if (token.Length == 0) continue;

            if (IsRemoteReference(raw)) return token;

            // rundll32 spells its payload "C:\path\thing.dll,EntryPoint".
            var comma = token.LastIndexOf(',');
            var candidate = comma > 0 ? token[..comma] : token;

            foreach (var extension in PayloadExtensions)
            {
                if (candidate.EndsWith(extension, StringComparison.OrdinalIgnoreCase)) return candidate;
            }
        }

        return null;
    }

    /// <summary>
    /// True when a PowerShell host appears anywhere in the command line, as the program or as a
    /// token further along (<c>cmd /c powershell …</c>).
    /// </summary>
    /// <remarks>
    /// This gate exists because nearly every marker below is the name of a <em>PowerShell</em>
    /// switch, and a single letter means whatever the program that receives it decides it means.
    /// Ungated, <c>sync.exe -e aBcD1234efGh5678IjKl</c> — a session token behind an ordinary
    /// <c>-e</c> flag — was reported as a command "written to be unreadable" at High. A switch
    /// name is only evidence when it is being handed to the interpreter that defines it.
    /// </remarks>
    internal static bool IsPowerShellCommand(string? command)
    {
        foreach (var token in Tokenise(command))
        {
            var leaf = token.Trim('"', '\'');

            var slash = leaf.LastIndexOfAny(['\\', '/']);
            if (slash >= 0) leaf = leaf[(slash + 1)..];

            var dot = leaf.LastIndexOf('.');
            if (dot > 0) leaf = leaf[..dot];

            if (leaf.Equals("powershell", StringComparison.OrdinalIgnoreCase)
                || leaf.Equals("pwsh", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Markers that mean the command line is hiding what it does. Kept separate from the weaker
    /// markers because these have no ordinary explanation: an installer has no reason to
    /// base64 its own arguments or to execute a string as code.
    /// </summary>
    internal static string? StrongObfuscationMarker(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;

        var tokens = Tokenise(command);

        // Switch-shaped markers are PowerShell's own spellings and mean nothing to another
        // program; the language-shaped ones below are read whatever the command line looks like.
        var powershell = IsPowerShellCommand(command);

        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i].Trim('\'');
            var lower = token.ToLowerInvariant();

            // Anchored to a whole token so that a folder called "Siex" cannot trip it.
            if (lower is "iex" || lower.StartsWith("iex(", StringComparison.Ordinal)) return token;

            if (lower.Contains("invoke-expression", StringComparison.Ordinal)) return "Invoke-Expression";
            if (lower.Contains("frombase64string", StringComparison.Ordinal)) return "FromBase64String";
            if (lower.Contains("downloadstring", StringComparison.Ordinal)) return "DownloadString";

            if (!powershell) continue;

            // -EncodedCommand and every abbreviation PowerShell accepts down to -enc. Matching
            // prefixes of the real switch name keeps an unrelated -encoding flag out of this.
            if (lower.Length >= 4
                && (lower[0] == '-' || lower[0] == '/')
                && "encodedcommand".StartsWith(lower[1..], StringComparison.Ordinal))
            {
                return token;
            }

            // -e <base64> is the same switch, abbreviated. Require the payload to look encoded
            // so that an unrelated -e flag on some other program stays silent.
            if ((lower is "-e" or "/e" or "-en" or "/en") && i + 1 < tokens.Count && LooksBase64(tokens[i + 1]))
                return token + " " + Ellipsis(tokens[i + 1]);

            // -WindowStyle Hidden, in any of the abbreviations PowerShell accepts.
            if ((lower is "-w" or "/w" || lower.StartsWith("-windowstyle", StringComparison.Ordinal))
                && i + 1 < tokens.Count
                && tokens[i + 1].StartsWith("h", StringComparison.OrdinalIgnoreCase))
            {
                return token + " " + tokens[i + 1];
            }

            if (lower is "-windowstyle=hidden" or "-w=hidden") return token;
        }

        return null;
    }

    /// <summary>
    /// Markers that are suggestive but genuinely common in legitimate tooling. Package managers
    /// and build scripts use <c>-NoProfile</c> and a relaxed execution policy all day long, so on
    /// their own these are worth a mention and not an alarm.
    /// </summary>
    /// <remarks>
    /// Gated on a PowerShell host for the same reason as the strong markers: <c>-nop</c> is a
    /// PowerShell switch, and on any other program it is just three letters.
    /// </remarks>
    internal static IReadOnlyList<string> WeakObfuscationMarkers(string? command)
    {
        if (string.IsNullOrWhiteSpace(command) || !IsPowerShellCommand(command)) return [];

        var found = new List<string>();
        var tokens = Tokenise(command);

        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            var lower = token.ToLowerInvariant();

            if (lower is "-nop" or "/nop" or "-noprofile" or "/noprofile") found.Add(token);
            else if (lower is "-noni" or "-noninteractive") found.Add(token);
            else if ((lower is "-ep" or "-executionpolicy" or "/executionpolicy")
                     && i + 1 < tokens.Count
                     && tokens[i + 1].StartsWith("b", StringComparison.OrdinalIgnoreCase))
            {
                found.Add(token + " " + tokens[i + 1]);
            }
        }

        return found;
    }

    /// <summary>True for a token long enough and uniform enough to be an encoded blob.</summary>
    private static bool LooksBase64(string token)
    {
        var value = token.Trim('"', '\'');
        if (value.Length < 20) return false;

        var upper = false;
        var lower = false;

        foreach (var c in value)
        {
            if (char.IsAsciiLetterUpper(c)) upper = true;
            else if (char.IsAsciiLetterLower(c)) lower = true;
            else if (!char.IsAsciiDigit(c) && c is not ('+' or '/' or '=')) return false;
        }

        return upper && lower;
    }

    /// <summary>Shortens a long blob for display; the Evidence line has to stay readable.</summary>
    internal static string Ellipsis(string value, int max = 48) =>
        value.Length <= max ? value : value[..max] + "\u2026";
}

/// <summary>A path a rule is about to judge, together with the sentence that explains where it came from.</summary>
internal readonly record struct InspectedPath(string Path, string Origin, StartupEntry? Entry);

/// <summary>
/// The paths a <see cref="SecurityScanContext"/> already knows about, pulled out once so the
/// structural rules do not each re-derive them. Nothing here reaches past the context.
/// </summary>
internal static class ContextPaths
{
    /// <summary>Every locatable program path in the context: auto-start targets and the programs an uninstall entry points at.</summary>
    internal static IEnumerable<InspectedPath> Executables(SecurityScanContext context)
    {
        foreach (var entry in context.StartupEntries)
        {
            var path = PathFacts.IsLocatable(entry.ExecutablePath)
                ? entry.ExecutablePath
                : CommandFacts.ExecutableFromCommand(entry.Command);

            if (PathFacts.IsLocatable(path))
            {
                yield return new InspectedPath(
                    path!,
                    $"\"{entry.DisplayName}\" is registered to run at sign-in ({entry.Source.DisplayName()}, {entry.Location})",
                    entry);
            }
        }

        foreach (var program in context.InstalledPrograms)
        {
            foreach (var raw in new[] { program.UninstallCommand, program.QuietUninstallCommand, program.IconPath })
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;

                var candidate = CommandFacts.ExecutableFromCommand(PathFacts.TrimIconIndex(raw));
                if (PathFacts.IsLocatable(candidate))
                {
                    yield return new InspectedPath(
                        candidate!,
                        $"the installed program \"{program.DisplayName}\" points at it",
                        null);
                }
            }
        }
    }

    /// <summary>
    /// Every token that might be a file name \u2014 arguments included, because a script host is
    /// usually handed the interesting file rather than being it.
    /// </summary>
    internal static IEnumerable<InspectedPath> FileNameTokens(SecurityScanContext context)
    {
        foreach (var entry in context.StartupEntries)
        {
            var origin = $"\"{entry.DisplayName}\" is registered to run at sign-in ({entry.Source.DisplayName()}, {entry.Location})";

            if (entry.ExecutablePath is { Length: > 0 } exe)
                yield return new InspectedPath(exe, origin, entry);

            foreach (var token in CommandFacts.Tokenise(entry.Command))
                yield return new InspectedPath(token.TrimEnd(','), origin, entry);
        }

        foreach (var program in context.InstalledPrograms)
        {
            var origin = $"the installed program \"{program.DisplayName}\" refers to it";

            if (program.InstallLocation is { Length: > 0 } location)
                yield return new InspectedPath(location, origin, null);

            if (program.IconPath is { Length: > 0 } icon)
                yield return new InspectedPath(PathFacts.TrimIconIndex(icon), origin, null);

            foreach (var command in new[] { program.UninstallCommand, program.QuietUninstallCommand })
            {
                foreach (var token in CommandFacts.Tokenise(command))
                    yield return new InspectedPath(token.TrimEnd(','), origin, null);
            }
        }
    }
}
