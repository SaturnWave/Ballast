using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text;
using Microsoft.Win32;

namespace Ballast.Core.Startup;

/// <summary>
/// Read-only enumeration of everything Windows launches at sign-in: the three Run keys, both
/// Startup folders, and scheduled tasks with a logon trigger. Mirrors the shape of
/// <see cref="Abstractions.IScanner"/> but yields <see cref="StartupEntry"/> instead of
/// cleanup items, so it deliberately does not implement that interface.
///
/// This class never writes anything. It also reads the parallel stores that
/// <see cref="StartupToggleService"/> uses for disabled items, so entries the user switched
/// off keep showing up (switched off, not missing).
///
/// Every registry, file and process access is individually guarded: one unreadable key or a
/// missing schtasks.exe degrades that one source to empty rather than failing the scan.
/// </summary>
public sealed class StartupScanner
{
    private static readonly string[] _folderExtensions = [".lnk", ".url", ".bat", ".cmd", ".exe"];

    private static readonly EnumerationOptions _fileOptions = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        // The default also skips Hidden and System. A hidden shortcut still runs at logon,
        // so we want to surface it; only reparse points stay off-limits.
        AttributesToSkip = FileAttributes.ReparsePoint,
    };

    // Locale-tolerant column lookup for `schtasks /fo CSV /v`. Compared after normalisation
    // (lower-cased, whitespace and colons removed), first for equality then as a substring.
    private static readonly string[] _taskNameHeaders =
        ["taskname", "aufgabenname", "nomdelatâche", "nomdelatache", "nombredetarea",
         "görevadı", "nomedatarefa", "nomeattività", "任务名", "タスク名"];

    private static readonly string[] _scheduleTypeHeaders =
        ["scheduletype", "zeitplantyp", "typedeplanification", "tipodeprogramación",
         "tipodeprogramacion", "zamanlamatürü", "tipodeagendamento", "tipopianificazione"];

    private static readonly string[] _taskStateHeaders =
        ["scheduledtaskstate", "taskstate", "statusofscheduledtask", "geplanteaufgabenstatus",
         "étatdelatâcheplanifiée", "estadodelatareaprogramada", "zamanlanmışgörevdurumu"];

    private static readonly string[] _statusHeaders = ["status", "estado", "état", "durum", "zustand"];

    private static readonly string[] _taskToRunHeaders =
        ["tasktorun", "auszuführendeaufgabe", "tâcheàexécuter", "tareaqueseejecutará",
         "çalıştırılacakgörev", "tarefaaserexecutada"];

    /// <summary>Tokens that mark a logon trigger in the localised "Schedule Type" column.</summary>
    private static readonly string[] _logonTokens =
        ["logon", "anmeldung", "ouverturedesession", "connexion", "iniciodesesión",
         "iniciodesesion", "oturum", "accesso", "登录", "ログオン"];

    /// <summary>Tokens that mark a disabled task. Anything unrecognised is treated as enabled.</summary>
    private static readonly string[] _disabledTokens =
        ["disabled", "deaktiviert", "désactivé", "desactivé", "desactivado", "deshabilitado",
         "disattivato", "desativado", "devredışı", "已禁用", "無効"];

    /// <summary>Label for the UI, matching <see cref="Abstractions.IScanner.Name"/>.</summary>
    public string Name => "Startup Items";

    /// <summary>
    /// Set false to skip the schtasks.exe round-trip entirely (it is the slow part of a scan).
    /// </summary>
    public bool IncludeScheduledTasks { get; init; } = true;

    /// <summary>
    /// Include tasks under <c>\Microsoft\</c>. Off by default: those are Windows' own logon
    /// tasks, they are not what a user means by "startup apps", and switching them off can
    /// break the OS.
    /// </summary>
    public bool IncludeMicrosoftTasks { get; init; }

    /// <summary>
    /// Collects every auto-start entry we can see. Ordered by source then name, de-duplicated
    /// (schtasks prints one row per trigger, so a task with two triggers appears twice).
    /// </summary>
    public async Task<IReadOnlyList<StartupEntry>> ScanAsync(CancellationToken ct = default)
    {
        // Start the slow source first so it overlaps the fast one instead of following it.
        var tasksJob = IncludeScheduledTasks
            ? ScanScheduledTasksAsync(ct)
            : Task.FromResult<IReadOnlyList<StartupEntry>>([]);

        var entries = await Task.Run(() => ScanLocalStores(ct), ct).ConfigureAwait(false);
        entries.AddRange(await tasksJob.ConfigureAwait(false));

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return entries
            .Where(e => seen.Add($"{(int)e.Source}\u001f{e.Location}\u001f{e.Name}"))
            .OrderBy(e => e.Source)
            .ThenBy(e => e.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// The registry keys and startup folders only — everything readable in milliseconds
    /// (measured on a real machine: ~55 ms, against ~8.4 s once scheduled tasks are included).
    ///
    /// <para>
    /// Scheduled tasks are expensive because <c>schtasks.exe /query /v</c> is the only way to see
    /// trigger types without administrator rights — the task XML under <c>System32\Tasks</c> is not
    /// readable by a standard user — and it dumps every task on the machine for us to parse. The UI
    /// therefore renders this list at once and folds <see cref="ScanScheduledTasksAsync"/> in when it
    /// arrives, instead of showing a spinner for eight seconds to gain a couple of rows.
    /// </para>
    /// </summary>
    public Task<IReadOnlyList<StartupEntry>> ScanFastAsync(CancellationToken ct = default)
        => Task.Run<IReadOnlyList<StartupEntry>>(() => Deduplicate(ScanLocalStores(ct)), ct);

    /// <summary>
    /// De-duplicates and orders entries. Safe to call on a partial list and again on the combined
    /// list, so a caller can merge the fast and slow phases as each completes.
    /// </summary>
    public static IReadOnlyList<StartupEntry> Deduplicate(IEnumerable<StartupEntry> entries)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unit = ((char)0x1f).ToString();

        return entries
            .Where(e => seen.Add(string.Join(unit, (int)e.Source, e.Location, e.Name)))
            .OrderBy(e => e.Source)
            .ThenBy(e => e.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static List<StartupEntry> ScanLocalStores(CancellationToken ct)
    {
        var entries = new List<StartupEntry>();

        foreach (var source in RegistrySources())
        {
            ct.ThrowIfCancellationRequested();
            ScanRegistry(source, entries, ct);
        }

        ScanFolder(StartupSource.StartupFolderUser, entries, ct);
        ScanFolder(StartupSource.StartupFolderCommon, entries, ct);

        return entries;
    }

    private static IEnumerable<StartupSource> RegistrySources()
    {
        yield return StartupSource.RegistryRunHkcu;
        yield return StartupSource.RegistryRunHklm;

        // On a 32-bit OS the Registry32 view is the same key we already read.
        if (Environment.Is64BitOperatingSystem)
            yield return StartupSource.RegistryRunHklmWow64;
    }

    private static void ScanRegistry(StartupSource source, List<StartupEntry> into, CancellationToken ct)
    {
        if (StartupBackingStore.Registry(source) is not { } location) return;

        RegistryKey baseKey;
        try
        {
            baseKey = RegistryKey.OpenBaseKey(location.Hive, location.View);
        }
        catch
        {
            // Hive unavailable (locked down, remote profile). That source is simply empty.
            return;
        }

        using (baseKey)
        {
            ReadRunKey(baseKey, location.RunSubKey, location.DisplayPath, source, isEnabled: true, into, ct);

            ReadRunKey(
                baseKey,
                location.DisabledSubKey,
                location.DisplayPath + StartupBackingStore.DisabledKeySuffix,
                source,
                isEnabled: false,
                into,
                ct);
        }
    }

    private static void ReadRunKey(
        RegistryKey baseKey,
        string subKey,
        string displayPath,
        StartupSource source,
        bool isEnabled,
        List<StartupEntry> into,
        CancellationToken ct)
    {
        RegistryKey? key;
        try
        {
            key = baseKey.OpenSubKey(subKey, writable: false);
        }
        catch
        {
            return;
        }

        if (key is null) return;

        using (key)
        {
            string[] names;
            try
            {
                names = key.GetValueNames();
            }
            catch
            {
                return;
            }

            foreach (var name in names)
            {
                ct.ThrowIfCancellationRequested();

                // An empty name is the key's default value, never a startup item.
                if (string.IsNullOrEmpty(name)) continue;

                try
                {
                    // DoNotExpandEnvironmentNames keeps REG_EXPAND_SZ values literal so the
                    // toggle service can move them back byte-for-byte.
                    var command = key
                        .GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                        ?.ToString();

                    if (string.IsNullOrWhiteSpace(command)) continue;

                    into.Add(StartupEntry.Create(name, command, source, displayPath, isEnabled));
                }
                catch
                {
                    // A single malformed value must not sink the whole scan.
                }
            }
        }
    }

    private static void ScanFolder(StartupSource source, List<StartupEntry> into, CancellationToken ct)
    {
        if (StartupBackingStore.Folder(source) is not { } folder) return;

        CollectFolder(folder, source, isEnabled: true, into, ct);

        // Items we parked. Windows does not launch anything in a subfolder of Startup, which
        // is exactly why moving a shortcut one level down is a safe, reversible "off".
        CollectFolder(
            Path.Combine(folder, StartupBackingStore.DisabledFolderName),
            source,
            isEnabled: false,
            into,
            ct);
    }

    private static void CollectFolder(
        string folder,
        StartupSource source,
        bool isEnabled,
        List<StartupEntry> into,
        CancellationToken ct)
    {
        FileInfo[] files;
        try
        {
            if (!Directory.Exists(folder)) return;
            files = new DirectoryInfo(folder).GetFiles("*", _fileOptions);
        }
        catch
        {
            return;
        }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();

            if (!_folderExtensions.Contains(file.Extension, StringComparer.OrdinalIgnoreCase)) continue;

            try
            {
                into.Add(FromStartupFile(file, source, isEnabled));
            }
            catch
            {
                // Unreadable shortcut: skip this one file.
            }
        }
    }

    private static StartupEntry FromStartupFile(FileInfo file, StartupSource source, bool isEnabled)
    {
        var name = Path.GetFileNameWithoutExtension(file.Name);

        if (file.Extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            var (target, arguments) = ResolveShortcut(file.FullName);

            var command = target is null
                ? file.FullName
                : arguments is null ? Quote(target) : $"{Quote(target)} {arguments}";

            return StartupEntry.Create(name, command, source, file.FullName, isEnabled, executablePath: target);
        }

        if (file.Extension.Equals(".url", StringComparison.OrdinalIgnoreCase))
        {
            var url = ReadInternetShortcut(file.FullName);

            // Only a real local path counts as an executable; an http target has no publisher.
            var executable = url is { Length: > 1 } u && (u[1] == ':' || u.StartsWith(@"\\", StringComparison.Ordinal))
                ? u
                : null;

            return StartupEntry.Create(name, url ?? file.FullName, source, file.FullName, isEnabled, executablePath: executable);
        }

        return StartupEntry.Create(name, file.FullName, source, file.FullName, isEnabled, executablePath: file.FullName);
    }

    private static string Quote(string value) => value.Contains(' ') ? $"\"{value}\"" : value;

    /// <summary>
    /// Reads a .lnk target by late-binding to the WScript.Shell COM object. Reflection keeps
    /// this module free of a shell-interop package; any failure (COM unavailable, a corrupt
    /// shortcut) degrades to an unknown target instead of losing the entry.
    /// </summary>
    private static (string? Target, string? Arguments) ResolveShortcut(string lnkPath)
    {
        try
        {
            if (Type.GetTypeFromProgID("WScript.Shell") is not { } shellType) return (null, null);
            if (Activator.CreateInstance(shellType) is not { } shell) return (null, null);

            var shortcut = shellType.InvokeMember(
                "CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object?[] { lnkPath });

            if (shortcut is null) return (null, null);

            var shortcutType = shortcut.GetType();
            var target = shortcutType.InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null) as string;
            var arguments = shortcutType.InvokeMember("Arguments", BindingFlags.GetProperty, null, shortcut, null) as string;

            return (Blank(target), Blank(arguments));
        }
        catch
        {
            return (null, null);
        }

        static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>Pulls the URL out of a .url internet shortcut (a plain INI file).</summary>
    private static string? ReadInternetShortcut(string path)
    {
        try
        {
            foreach (var line in File.ReadLines(path))
            {
                if (!line.StartsWith("URL=", StringComparison.OrdinalIgnoreCase)) continue;

                var value = line[4..].Trim();
                return value.Length == 0 ? null : value;
            }
        }
        catch
        {
            // Locked or unreadable file.
        }

        return null;
    }

    /// <summary>
    /// The slow half of a scan: logon-triggered scheduled tasks, via <c>schtasks.exe</c>.
    /// Public so the UI can run it in the background after <see cref="ScanFastAsync"/> has already
    /// painted. Never throws — a missing or unresponsive schtasks yields an empty list.
    /// </summary>
    public async Task<IReadOnlyList<StartupEntry>> ScanScheduledTasksAsync(CancellationToken ct = default)
    {
        SchTasks.Result result;
        try
        {
            result = await SchTasks.RunAsync(["/query", "/fo", "CSV", "/v"], ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return [];
        }

        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StandardOutput)) return [];

        try
        {
            return ParseTasks(result.StandardOutput, IncludeMicrosoftTasks);
        }
        catch
        {
            // Any surprise in the CSV means "no tasks", never a failed scan.
            return [];
        }
    }

    private static IReadOnlyList<StartupEntry> ParseTasks(string csv, bool includeMicrosoft)
    {
        var records = SchTasks.ParseCsv(csv);
        if (records.Count < 2) return [];

        var header = records[0];
        var nameColumn = SchTasks.FindColumn(header, _taskNameHeaders);
        var typeColumn = SchTasks.FindColumn(header, _scheduleTypeHeaders);
        var runColumn = SchTasks.FindColumn(header, _taskToRunHeaders);

        var stateColumn = SchTasks.FindColumn(header, _taskStateHeaders);
        if (stateColumn < 0) stateColumn = SchTasks.FindColumn(header, _statusHeaders);

        // Without both the name and the trigger column we cannot tell a logon task from a
        // nightly maintenance job. Showing the wrong rows here would invite the user to
        // disable something load-bearing, so we show none.
        if (nameColumn < 0 || typeColumn < 0) return [];

        var entries = new List<StartupEntry>();

        for (var i = 1; i < records.Count; i++)
        {
            var row = records[i];
            if (row.Length <= Math.Max(nameColumn, typeColumn)) continue;

            var taskPath = row[nameColumn].Trim();

            // Real task names are absolute. This also drops repeated header blocks and the
            // "INFO: There are no scheduled tasks..." line.
            if (taskPath.Length == 0 || taskPath[0] != '\\') continue;

            if (!includeMicrosoft && taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!SchTasks.ContainsAny(row[typeColumn], _logonTokens)) continue;

            var command = runColumn >= 0 && runColumn < row.Length ? row[runColumn].Trim() : string.Empty;

            var isEnabled = !(stateColumn >= 0
                && stateColumn < row.Length
                && SchTasks.ContainsAny(row[stateColumn], _disabledTokens));

            var leaf = taskPath[(taskPath.LastIndexOf('\\') + 1)..];

            entries.Add(StartupEntry.Create(
                name: leaf.Length > 0 ? leaf : taskPath,
                command: command,
                source: StartupSource.ScheduledTask,
                location: taskPath,
                isEnabled: isEnabled));
        }

        return entries;
    }
}

/// <summary>
/// Thin wrapper over schtasks.exe plus the CSV plumbing around it. Shared by
/// <see cref="StartupScanner"/> (querying) and <see cref="StartupToggleService"/> (changing),
/// so the process is launched the same guarded way in both directions.
/// </summary>
internal static class SchTasks
{
    private static readonly TimeSpan _timeout = TimeSpan.FromSeconds(45);
    private static readonly Encoding? _consoleEncoding = TryGetConsoleEncoding();

    /// <summary>Outcome of one schtasks.exe invocation.</summary>
    internal readonly record struct Result(int ExitCode, string StandardOutput, string StandardError);

    /// <summary>
    /// Runs schtasks.exe with the given arguments. Arguments go through
    /// <see cref="ProcessStartInfo.ArgumentList"/> so nothing is ever quoted by hand, and
    /// <see cref="ProcessStartInfo.UseShellExecute"/> stays false so there is no shell to inject into.
    /// </summary>
    internal static async Task<Result> RunAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = ResolveExecutable(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        if (_consoleEncoding is { } encoding)
        {
            startInfo.StandardOutputEncoding = encoding;
            startInfo.StandardErrorEncoding = encoding;
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start schtasks.exe.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_timeout);

        // Drain both pipes concurrently: a full stderr buffer would otherwise deadlock the child.
        var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        var stderr = process.StandardError.ReadToEndAsync(deadline.Token);

        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);

            return new Result(
                process.ExitCode,
                await stdout.ConfigureAwait(false),
                await stderr.ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            TryKill(process);

            // Observe both readers so neither faults unobserved.
            try { await Task.WhenAll(stdout, stderr).ConfigureAwait(false); } catch { }

            ct.ThrowIfCancellationRequested();
            throw new TimeoutException(
                $"schtasks.exe did not respond within {_timeout.TotalSeconds:0} seconds.");
        }
    }

    /// <summary>
    /// Splits RFC 4180-ish CSV into records. Handles quoted fields containing commas, doubled
    /// quotes and newlines (task comments do all three). Blank lines are dropped.
    /// </summary>
    internal static List<string[]> ParseCsv(string text)
    {
        var records = new List<string[]>();
        var fields = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;
        var anyContent = false;

        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];

            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"')
                    {
                        field.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(ch);
                }

                continue;
            }

            switch (ch)
            {
                case '"':
                    inQuotes = true;
                    anyContent = true;
                    break;

                case ',':
                    fields.Add(field.ToString());
                    field.Clear();
                    anyContent = true;
                    break;

                case '\r':
                    break;

                case '\n':
                    fields.Add(field.ToString());
                    field.Clear();
                    if (anyContent) records.Add([.. fields]);
                    fields.Clear();
                    anyContent = false;
                    break;

                default:
                    field.Append(ch);
                    anyContent = true;
                    break;
            }
        }

        if (anyContent)
        {
            fields.Add(field.ToString());
            records.Add([.. fields]);
        }

        return records;
    }

    /// <summary>
    /// Finds a column by header name: exact match on the normalised header first, then a
    /// substring match. Returns -1 when the header is in a language we do not recognise —
    /// callers must treat that as "no data", never as a parse error.
    /// </summary>
    internal static int FindColumn(IReadOnlyList<string> header, IReadOnlyList<string> candidates)
    {
        for (var i = 0; i < header.Count; i++)
        {
            if (candidates.Contains(Normalize(header[i]), StringComparer.Ordinal)) return i;
        }

        for (var i = 0; i < header.Count; i++)
        {
            var normalized = Normalize(header[i]);
            if (normalized.Length > 0 && candidates.Any(c => normalized.Contains(c, StringComparison.Ordinal)))
                return i;
        }

        return -1;
    }

    /// <summary>True when <paramref name="value"/> contains one of the pre-normalised tokens.</summary>
    internal static bool ContainsAny(string? value, IReadOnlyList<string> tokens)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;

        var normalized = Normalize(value);
        return tokens.Any(t => normalized.Contains(t, StringComparison.Ordinal));
    }

    /// <summary>Lower-cases and strips the punctuation that varies between Windows builds.</summary>
    internal static string Normalize(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var ch in value)
        {
            if (char.IsWhiteSpace(ch) || ch is ':' or '\'' or '-' or '.' or '_') continue;
            builder.Append(char.ToLowerInvariant(ch));
        }

        return builder.ToString();
    }

    /// <summary>Full path to schtasks.exe, so PATH cannot be used to substitute it.</summary>
    private static string ResolveExecutable()
    {
        try
        {
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var full = Path.Combine(system, "schtasks.exe");
            if (File.Exists(full)) return full;
        }
        catch
        {
            // Fall through to the bare name.
        }

        return "schtasks.exe";
    }

    private static Encoding? TryGetConsoleEncoding()
    {
        try
        {
            // Console tools write in the OEM code page; that encoding is not always registered
            // on .NET, hence the guard.
            return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        }
        catch
        {
            return null;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Already gone, or we cannot touch it. Nothing else to do.
        }
    }
}
