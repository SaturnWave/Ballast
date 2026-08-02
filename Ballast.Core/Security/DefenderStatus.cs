using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Ballast.Core.Util;

namespace Ballast.Core.Security;

/// <summary>
/// Read-only window onto Microsoft Defender.
///
/// <para>
/// <b>Ballast reads Defender's mind; it does not drive it.</b> This type queries state that Defender
/// already knows and, when the user presses a button, asks Defender to start a scan. It will never
/// disable protection, never remove or release a quarantined item, never manage exclusions and never
/// call <c>Remove-MpThreat</c>. Real detection is Defender's job and we defer to it explicitly —
/// Ballast is not an antivirus and must not behave like one.
/// </para>
///
/// <para>
/// Everything here degrades to "could not determine" rather than guessing. Defender is genuinely
/// absent or unreachable on plenty of healthy machines — Server SKUs without the feature installed,
/// images where it was removed, and above all machines running a third-party antivirus, which puts
/// Defender into passive mode. Reporting "protection is off" on any of those would be both wrong and
/// alarming, so <see cref="GetAsync"/> returns <see langword="null"/> when it cannot read the state,
/// and <see cref="DefenderSnapshot.IsActiveProvider"/> is itself nullable.
/// </para>
/// </summary>
public sealed class DefenderStatus
{
    /// <summary>
    /// PowerShell can hang on a wedged WMI/CIM service. Bound it: an unanswered query is the same
    /// as "could not determine", and the UI would rather say that than spin forever.
    /// </summary>
    private static readonly TimeSpan _queryTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long we wait to see whether <c>MpCmdRun.exe</c> falls over immediately. A real scan runs
    /// for minutes or hours; we are only trying to catch "bad arguments" or "access denied".
    /// </summary>
    private static readonly TimeSpan _launchGrace = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Full path to the PowerShell host. Defaults to the Windows PowerShell under
    /// <c>System32</c> — an absolute path, so <c>PATH</c> cannot be used to substitute a different
    /// binary into an elevated process.
    ///
    /// <para>
    /// Overridable so a test can point at a host that does not exist, or one that answers with
    /// something other than JSON, and prove that "Defender unavailable" degrades to
    /// <see langword="null"/> instead of throwing.
    /// </para>
    /// </summary>
    public string PowerShellPath { get; init; } = ResolvePowerShell();

    /// <summary>
    /// Reads Defender's current state in one round-trip.
    ///
    /// <para>
    /// Returns <see langword="null"/> — never throws, and never a half-built snapshot — when
    /// <c>Get-MpComputerStatus</c> is missing, blocked by policy, or does not answer in time. The
    /// caller must render that as "could not determine", not as "unprotected".
    /// </para>
    /// </summary>
    public async Task<DefenderSnapshot?> GetAsync(CancellationToken ct = default)
    {
        var result = await RunPowerShellAsync(_statusScript, ct).ConfigureAwait(false);

        if (result is not { ExitCode: 0 } ok || string.IsNullOrWhiteSpace(ok.StandardOutput))
            return null;

        return ParseStatusJson(ok.StandardOutput);
    }

    /// <summary>
    /// What Defender has flagged recently, straight from its own history
    /// (<c>Get-MpThreatDetection</c> joined to <c>Get-MpThreat</c> on the threat id).
    ///
    /// <para>
    /// These are Defender's findings reported verbatim, not Ballast's. An empty list means either
    /// "nothing recorded" or "could not read" — deliberately indistinguishable, because neither is a
    /// statement about whether the machine is clean, and the UI must not imply otherwise.
    /// </para>
    ///
    /// <para>
    /// A record Defender cannot date is left out: the contract of this method is "within the last
    /// <paramref name="days"/> days", and an entry we cannot place in time is not known to be inside
    /// that window. Same principle as the deletion guards — cannot tell means do not claim.
    /// </para>
    /// </summary>
    /// <param name="days">Look-back window, clamped to 1–3650 days.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<IReadOnlyList<DefenderDetection>> GetRecentDetectionsAsync(
        int days = 30,
        CancellationToken ct = default)
    {
        // Interpolated into the script as an integer, so there is no string for a caller to inject.
        var window = Math.Clamp(days, 1, 3650).ToString(CultureInfo.InvariantCulture);

        var result = await RunPowerShellAsync(
            _detectionsScriptPrefix + window + _detectionsScriptSuffix, ct).ConfigureAwait(false);

        if (result is not { ExitCode: 0 } ok || string.IsNullOrWhiteSpace(ok.StandardOutput))
            return [];

        return ParseDetectionsJson(ok.StandardOutput);
    }

    /// <summary>
    /// Asks Defender to scan, via <c>MpCmdRun.exe</c>.
    ///
    /// <para>
    /// <b>Only ever call this from an explicit user action.</b> Never on a timer, never at startup,
    /// never as part of a background sweep. A scan is expensive and is the user's decision.
    /// </para>
    ///
    /// <para>
    /// Returns whether the scan process <i>started</i> — not whether anything was found. The scan
    /// keeps running after this method returns; cancelling <paramref name="ct"/> only stops us
    /// waiting, it does not abort a scan Defender has already begun.
    /// </para>
    ///
    /// <para>
    /// Note for callers writing UI text: what Defender does with anything it finds is governed by
    /// the user's own Defender settings, which may include quarantining a file. That is Defender
    /// acting under its own policy, not Ballast deleting something — but the button should still not
    /// pretend the operation is purely observational.
    /// </para>
    /// </summary>
    /// <param name="path">A file or folder to scan. <see langword="null"/> scans the computer.</param>
    /// <param name="quickScan">Quick scan when true, full scan when false. Ignored if a path is given.</param>
    /// <param name="ct">Cancellation token; stops us waiting, does not stop the scan.</param>
    public async Task<bool> StartScanAsync(
        string? path = null,
        bool quickScan = true,
        CancellationToken ct = default)
    {
        var target = path is null ? "(whole computer)" : path;
        var kind = path is not null ? "custom" : quickScan ? "quick" : "full";

        if (ResolveMpCmdRunPath() is not { } mpCmdRun)
        {
            ActionLog.Info($"DEFENDER {kind} scan not started for {target} -- MpCmdRun.exe was not found");
            return false;
        }

        var arguments = new List<string> { "-Scan" };

        if (path is null)
        {
            arguments.Add("-ScanType");
            arguments.Add(quickScan ? "1" : "2");
        }
        else
        {
            // Refuse before launching rather than letting MpCmdRun fail obscurely on a stale path.
            bool exists;
            try
            {
                exists = File.Exists(path) || Directory.Exists(path);
            }
            catch
            {
                exists = false;
            }

            if (!exists)
            {
                ActionLog.Info($"DEFENDER {kind} scan not started -- no such file or folder: {path}");
                return false;
            }

            arguments.Add("-ScanType");
            arguments.Add("3");
            arguments.Add("-File");
            arguments.Add(path);
        }

        var startInfo = BuildStartInfo(mpCmdRun, arguments);

        Process process;
        try
        {
            if (Process.Start(startInfo) is not { } started)
            {
                ActionLog.Info($"DEFENDER {kind} scan not started for {target} -- no process was created");
                return false;
            }

            process = started;
        }
        catch (Exception ex)
        {
            ActionLog.Info($"DEFENDER {kind} scan not started for {target} -- {ex.Message}");
            return false;
        }

        // Drain both pipes from the moment the process exists. A scan is chatty and a full stderr
        // buffer would wedge the child; these run to completion in the background because we are
        // not waiting for the scan itself.
        var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);

        bool launched;
        using (var grace = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            grace.CancelAfter(_launchGrace);

            try
            {
                await process.WaitForExitAsync(grace.Token).ConfigureAwait(false);

                // It came back inside the grace window, so it never really scanned anything.
                launched = process.ExitCode == 0;
            }
            catch (OperationCanceledException)
            {
                // Still running: that is the normal, successful case.
                launched = true;
            }
        }

        _ = ReapAsync(process, stdout, stderr);

        ActionLog.Info(launched
            ? $"DEFENDER {(path is null && !quickScan ? "full" : "quick")} scan started for {target}"
            : $"DEFENDER scan failed to start for {target}");

        return launched;
    }

    /// <summary>
    /// Locates <c>MpCmdRun.exe</c>, or <see langword="null"/> if Defender's command-line tool is not
    /// on this machine.
    ///
    /// <para>
    /// The copy in <c>%ProgramFiles%\Windows Defender</c> is the documented entry point, but on a
    /// machine that has taken a platform update it is a stub and the working binary lives under
    /// <c>%ProgramData%\Microsoft\Windows Defender\Platform\&lt;version&gt;</c>. Both are probed, and
    /// the newest platform version wins — hard-coding either one is how this breaks silently on
    /// somebody else's machine.
    /// </para>
    /// </summary>
    public static string? ResolveMpCmdRunPath()
    {
        foreach (var root in ProgramFilesRoots())
        {
            try
            {
                var candidate = Path.Combine(root, "Windows Defender", "MpCmdRun.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch
            {
                // A malformed environment variable is just a candidate that does not apply.
            }
        }

        return NewestPlatformMpCmdRun();
    }

    private static IEnumerable<string> ProgramFilesRoots()
    {
        // ProgramW6432 first: it is the native 64-bit Program Files even when this process is
        // 32-bit, and there is no Defender under the x86 tree.
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("ProgramW6432"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetEnvironmentVariable("ProgramFiles"),
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate)) continue;
            if (seen.Add(candidate)) yield return candidate;
        }
    }

    private static string? NewestPlatformMpCmdRun()
    {
        try
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrWhiteSpace(programData)) return null;

            var platformRoot = Path.Combine(programData, "Microsoft", "Windows Defender", "Platform");
            if (!Directory.Exists(platformRoot)) return null;

            string? best = null;
            var bestVersion = new Version(0, 0);
            var bestStamp = DateTime.MinValue;

            foreach (var directory in Directory.EnumerateDirectories(platformRoot))
            {
                var executable = Path.Combine(directory, "MpCmdRun.exe");
                if (!File.Exists(executable)) continue;

                // Directory names look like "4.18.26060.3008-0"; the suffix is not part of the version.
                var name = Path.GetFileName(directory);
                var dash = name.IndexOf('-');
                _ = Version.TryParse(dash > 0 ? name[..dash] : name, out var version);

                var stamp = Directory.GetLastWriteTimeUtc(directory);

                if (best is not null && !IsNewer(version, stamp, bestVersion, bestStamp)) continue;

                best = executable;
                bestVersion = version ?? new Version(0, 0);
                bestStamp = stamp;
            }

            return best;
        }
        catch
        {
            return null;
        }

        static bool IsNewer(Version? version, DateTime stamp, Version bestVersion, DateTime bestStamp)
        {
            if (version is null) return stamp > bestStamp;

            var comparison = version.CompareTo(bestVersion);
            return comparison != 0 ? comparison > 0 : stamp > bestStamp;
        }
    }

    /// <summary>
    /// Turns one <c>Get-MpComputerStatus</c> JSON document into a snapshot, or
    /// <see langword="null"/> if it is not a readable object.
    ///
    /// <para>
    /// Public because it is the seam that makes this class testable on a machine where Defender is
    /// absent, disabled or in an unusual state — the parser can be exercised against captured JSON
    /// without a live Defender anywhere in sight. It never throws: every field is optional, and an
    /// unexpected shape yields <see langword="null"/> for that field rather than a failed read.
    /// Windows PowerShell has a habit of serialising an absent value as <c>{}</c> rather than
    /// <c>null</c>, which is exactly the kind of surprise this has to absorb.
    /// </para>
    /// </summary>
    public static DefenderSnapshot? ParseStatusJson(string json)
    {
        var root = TryParse(json);
        if (root is not { ValueKind: JsonValueKind.Object } status) return null;

        var raw = Str(status, "RunningMode");

        return new DefenderSnapshot
        {
            RunningMode = ParseRunningMode(raw),
            RunningModeRaw = raw,
            ServiceEnabled = Bool(status, "ServiceEnabled"),
            AntivirusEnabled = Bool(status, "AntivirusEnabled"),
            RealTimeProtectionEnabled = Bool(status, "RealTimeProtectionEnabled"),
            BehaviourMonitoringEnabled = Bool(status, "BehaviorMonitorEnabled"),
            TamperProtectionEnabled = Bool(status, "TamperProtected"),
            SignatureVersion = Str(status, "SignatureVersion"),
            SignatureAgeDays = Age(status, "SignatureAgeDays"),
            SignatureLastUpdatedUtc = Date(status, "SignatureLastUpdated"),
            LastQuickScanUtc = Date(status, "LastQuickScan"),
            LastFullScanUtc = Date(status, "LastFullScan"),
            SignaturesOutOfDate = Bool(status, "SignaturesOutOfDate"),
            RegisteredProviders = Strings(status, "RegisteredProviders"),
            CapturedAtUtc = DateTimeOffset.UtcNow,
        };
    }

    /// <summary>
    /// Turns the detections JSON into records. Returns an empty list for anything unreadable —
    /// public for the same reason as <see cref="ParseStatusJson"/>, and equally incapable of
    /// throwing.
    /// </summary>
    public static IReadOnlyList<DefenderDetection> ParseDetectionsJson(string json)
    {
        var root = TryParse(json);
        if (root is not { ValueKind: JsonValueKind.Object } document) return [];

        if (!document.TryGetProperty("Items", out var items) || items.ValueKind != JsonValueKind.Array)
            return [];

        var detections = new List<DefenderDetection>();

        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;

            // Undateable records are dropped upstream in the script; this is the belt to that
            // braces, because a detection with no time cannot honestly be called "recent".
            if (Date(item, "DetectedUtc") is not { } detectedUtc) continue;

            var resources = Strings(item, "Resources");
            var statusId = Number(item, "StatusId") ?? 0;
            var actionId = Number(item, "ActionId") ?? 0;

            detections.Add(new DefenderDetection
            {
                ThreatName = Str(item, "ThreatName") ?? "Unnamed detection",
                Severity = ParseSeverity(Number(item, "SeverityId")),
                DetectedUtc = detectedUtc,
                ActionTaken = DescribeAction(statusId, actionId),
                ActionSucceeded = Bool(item, "ActionSucceeded"),
                TargetPath = FirstFileResource(resources),
                Resources = resources,
                ProcessName = Str(item, "ProcessName"),
            });
        }

        // Newest first: that is the order a human reads a history in.
        detections.Sort((a, b) => b.DetectedUtc.CompareTo(a.DetectedUtc));
        return detections;
    }

    private static DefenderRunningMode ParseRunningMode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return DefenderRunningMode.Unknown;

        // Documented values are "Normal", "Passive", "SxS Passive Mode", "EDR Block Mode" and
        // "Not running". Substring matching so a new wording does not silently become Unknown.
        if (Has(raw, "not running")) return DefenderRunningMode.NotRunning;
        if (Has(raw, "edr")) return DefenderRunningMode.EdrBlock;
        if (Has(raw, "passive")) return DefenderRunningMode.Passive;
        if (Has(raw, "normal")) return DefenderRunningMode.Normal;

        return DefenderRunningMode.Unknown;

        static bool Has(string value, string token) =>
            value.Contains(token, StringComparison.OrdinalIgnoreCase);
    }

    private static DefenderThreatSeverity ParseSeverity(long? id) => id switch
    {
        1 => DefenderThreatSeverity.Low,
        2 => DefenderThreatSeverity.Moderate,
        4 => DefenderThreatSeverity.High,
        5 => DefenderThreatSeverity.Severe,
        _ => DefenderThreatSeverity.Unknown,
    };

    /// <summary>
    /// Plain-language version of Defender's numeric status. Codes outside the documented set are
    /// rendered as the code itself: inventing a label for a number we do not recognise would put
    /// words in Defender's mouth, and "Removed" is not a word to guess at.
    /// </summary>
    private static string DescribeAction(long statusId, long actionId) => statusId switch
    {
        2 => "Cleaned",
        3 => "Quarantined",
        4 => "Removed",
        5 => "Allowed",
        6 => "Blocked",
        1 => DescribeCleaningAction(actionId) ?? "Detected",
        0 => DescribeCleaningAction(actionId) ?? "Not recorded",
        _ => $"Defender status code {statusId.ToString(CultureInfo.InvariantCulture)}",
    };

    private static string? DescribeCleaningAction(long actionId) => actionId switch
    {
        1 => "Cleaned",
        2 => "Quarantined",
        3 => "Removed",
        6 => "Allowed",
        9 => "No action taken",
        10 => "Blocked",
        _ => null,
    };

    /// <summary>
    /// Defender resource strings are prefixed by kind: <c>file:_C:\path</c>, <c>process:_…</c>,
    /// <c>regkey:_…</c>, <c>webfile:_…</c>. Only the file kinds name something a user can actually go
    /// and look at, so nothing else is promoted to a path — a registry key or a pid shown where a
    /// filename belongs is a lie the UI would faithfully repeat.
    /// </summary>
    private static string? FirstFileResource(IReadOnlyList<string> resources)
    {
        string[] filePrefixes = ["file:_", "containerfile:_"];

        foreach (var prefix in filePrefixes)
        {
            foreach (var resource in resources)
            {
                if (resource.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return Blank(resource[prefix.Length..]);
            }
        }

        return null;
    }

    private static JsonElement? TryParse(string json)
    {
        try
        {
            // Windows PowerShell can prepend a UTF-8 BOM once the console encoding is switched.
            using var document = JsonDocument.Parse(json.Trim().TrimStart('\uFEFF'));
            return document.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static string? Str(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? Blank(value.GetString())
            : null;

    private static bool? Bool(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value)) return null;

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null,
        };
    }

    private static long? Number(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value)) return null;

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt64(out var number) => number,
            JsonValueKind.String when long.TryParse(
                value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };
    }

    /// <summary>
    /// An age in days, or <see langword="null"/> for "never" / "unknown".
    ///
    /// <para>
    /// Defender reports an unknown age as <see cref="uint.MaxValue"/>. Rendering that literally
    /// would tell the user their signatures are eleven million days old — the same class of mistake
    /// as showing a 4 GB program as "0 KB" because the registry said zero. Anything past a decade is
    /// treated as no answer at all.
    /// </para>
    /// </summary>
    private static int? Age(JsonElement parent, string name)
    {
        if (Number(parent, name) is not { } days) return null;
        return days is < 0 or > 3650 ? null : (int)days;
    }

    private static DateTimeOffset? Date(JsonElement parent, string name)
    {
        if (Str(parent, name) is not { } text) return null;

        if (DateTimeOffset.TryParse(
                text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
            return parsed.ToUniversalTime();

        // Fallback for the raw Windows PowerShell serialisation, "/Date(1785476727000)/", in case a
        // future host stops normalising to round-trip format for us.
        const string prefix = "/Date(";
        if (!text.StartsWith(prefix, StringComparison.Ordinal)) return null;

        var end = text.IndexOf(')', prefix.Length);
        if (end < 0) return null;

        var digits = text[prefix.Length..end];

        // The offset suffix, when present, is already baked into the millisecond value.
        var sign = digits.IndexOfAny(['+', '-'], 1);
        if (sign > 0) digits = digits[..sign];

        if (!long.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out var milliseconds))
            return null;

        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> Strings(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
            return [];

        var items = new List<string>();

        foreach (var element in value.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String) continue;
            if (Blank(element.GetString()) is { } text) items.Add(text);
        }

        return items;
    }

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private readonly record struct ProcessResult(int ExitCode, string StandardOutput);

    /// <summary>
    /// Runs one self-contained PowerShell script and hands back its stdout.
    ///
    /// <para>
    /// <c>-NoProfile</c> so a user's profile cannot change what we read, <c>-NonInteractive</c> so
    /// nothing can ever sit waiting on a prompt we cannot answer. We deliberately do <b>not</b> pass
    /// <c>-ExecutionPolicy Bypass</c>: reading Defender's status is not worth talking our way past
    /// the machine's own security configuration, and if a policy does block us, "could not
    /// determine" is the correct answer.
    /// </para>
    /// </summary>
    private async Task<ProcessResult?> RunPowerShellAsync(string script, CancellationToken ct)
    {
        // Do not spawn a process we already know we will abandon.
        if (ct.IsCancellationRequested) return null;

        var startInfo = BuildStartInfo(PowerShellPath, ["-NoProfile", "-NonInteractive", "-Command", script]);

        // The scripts ask the child for UTF-8, so decode it as UTF-8. The OEM code page would
        // mangle a non-ASCII file path in a detection record, and those are common.
        startInfo.StandardOutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        startInfo.StandardErrorEncoding = startInfo.StandardOutputEncoding;

        Process process;
        try
        {
            if (Process.Start(startInfo) is not { } started) return null;
            process = started;
        }
        catch
        {
            // No PowerShell, or we are not allowed to start it. Same answer either way.
            return null;
        }

        using (process)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(_queryTimeout);

            // Drain both pipes concurrently: a full stderr buffer would otherwise deadlock the child.
            var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = process.StandardError.ReadToEndAsync(deadline.Token);

            try
            {
                await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);

                var output = await stdout.ConfigureAwait(false);
                _ = await stderr.ConfigureAwait(false);

                return new ProcessResult(process.ExitCode, output);
            }
            catch (OperationCanceledException)
            {
                TryKill(process);

                // Observe both readers so neither faults unobserved.
                try { await Task.WhenAll(stdout, stderr).ConfigureAwait(false); } catch { }

                // A caller-cancelled read is still just "no answer"; this method never throws so
                // that a shutting-down page does not have to catch anything.
                return null;
            }
            catch
            {
                return null;
            }
        }
    }

    private static ProcessStartInfo BuildStartInfo(string fileName, IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            UseShellExecute = false,
        };

        // ArgumentList, so nothing is ever quoted by hand and there is no shell to inject into.
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        return startInfo;
    }

    /// <summary>
    /// Keeps a long-running child's pipes drained and releases its handle when it finally exits,
    /// without anybody waiting on it.
    /// </summary>
    private static async Task ReapAsync(Process process, Task<string> stdout, Task<string> stderr)
    {
        try
        {
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        }
        catch
        {
            // Nothing to salvage: we were never reading this output for its content.
        }
        finally
        {
            try { process.Dispose(); } catch { }
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

    /// <summary>Absolute path to Windows PowerShell, so <c>PATH</c> cannot substitute a stand-in.</summary>
    private static string ResolvePowerShell()
    {
        try
        {
            var candidate = Path.Combine(
                Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

            if (File.Exists(candidate)) return candidate;
        }
        catch
        {
            // Fall through to the bare name.
        }

        return "powershell.exe";
    }

    /// <summary>
    /// The scripts are assembled from single-line fragments joined by spaces, and contain no
    /// double-quote characters anywhere. That is not a style choice: <c>powershell.exe -Command</c>
    /// re-parses the raw command line, so a quote that .NET escapes on the way out arrives as a
    /// literal backslash-quote and the script stops being the script we wrote. Single quotes and
    /// explicit statement semicolons keep the argument round-trip lossless — and keep the whole
    /// thing readable, rather than hiding it behind <c>-EncodedCommand</c>, which would make an app
    /// that reads Defender's mind look, to Defender, exactly like something worth investigating.
    /// </summary>
    private static readonly string _statusScript = string.Join(' ',
        // Best effort: if the encoding switch fails, ASCII still survives and only exotic
        // characters degrade. Failing the whole read over it would be worse.
        "try{[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding $false}catch{};",
        "$ErrorActionPreference='Stop';",
        "try{",
        "$s=Get-MpComputerStatus;",
        "if($null -eq $s){exit 3};",
        // SecurityCenter2 lists every registered antivirus. It is absent on Server SKUs, hence the
        // inner catch: not knowing who else is installed must not cost us the whole status read.
        "$av=@();",
        "try{$av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct",
        "-ErrorAction Stop|ForEach-Object{[string]$_.displayName})}catch{$av=@()};",
        "[pscustomobject]@{",
        "RunningMode=[string]$s.AMRunningMode;",
        // Each flag is emitted as $null when Defender does not report it. An older platform simply
        // lacks some of these, and absent must not collapse into "false" — "off" and "unknown" are
        // very different things to show a user.
        "ServiceEnabled=$(if($null -ne $s.AMServiceEnabled){[bool]$s.AMServiceEnabled}else{$null});",
        "AntivirusEnabled=$(if($null -ne $s.AntivirusEnabled){[bool]$s.AntivirusEnabled}else{$null});",
        "RealTimeProtectionEnabled=$(if($null -ne $s.RealTimeProtectionEnabled)",
        "{[bool]$s.RealTimeProtectionEnabled}else{$null});",
        "BehaviorMonitorEnabled=$(if($null -ne $s.BehaviorMonitorEnabled)",
        "{[bool]$s.BehaviorMonitorEnabled}else{$null});",
        "TamperProtected=$(if($null -ne $s.IsTamperProtected){[bool]$s.IsTamperProtected}else{$null});",
        "SignatureVersion=[string]$s.AntivirusSignatureVersion;",
        "SignatureAgeDays=[string]$s.AntivirusSignatureAge;",
        // Normalised to round-trip UTC here rather than in C#, so the host's own DateTime
        // serialisation ("/Date(…)/" on Windows PowerShell, ISO-8601 on PowerShell 7) stops
        // mattering. The explicit else is load-bearing: an if with no else serialises as {}.
        "SignatureLastUpdated=$(if($s.AntivirusSignatureLastUpdated)",
        "{([datetime]$s.AntivirusSignatureLastUpdated).ToUniversalTime().ToString('o')}else{$null});",
        "LastQuickScan=$(if($s.QuickScanEndTime)",
        "{([datetime]$s.QuickScanEndTime).ToUniversalTime().ToString('o')}else{$null});",
        "LastFullScan=$(if($s.FullScanEndTime)",
        "{([datetime]$s.FullScanEndTime).ToUniversalTime().ToString('o')}else{$null});",
        "SignaturesOutOfDate=$(if($null -ne $s.DefenderSignaturesOutOfDate)",
        "{[bool]$s.DefenderSignaturesOutOfDate}else{$null});",
        "RegisteredProviders=[string[]]$av;",
        "}|ConvertTo-Json -Compress -Depth 3",
        "}catch{exit 3}");

    private static readonly string _detectionsScriptPrefix = string.Join(' ',
        "try{[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding $false}catch{};",
        "$ErrorActionPreference='Stop';",
        "try{",
        "$since=(Get-Date).AddDays(-");

    private static readonly string _detectionsScriptSuffix = string.Join(' ',
        ");",
        // Get-MpThreatDetection knows when and where; Get-MpThreat knows the name and severity.
        // Neither alone is a useful row, so they are joined on ThreatID. A missing threat table is
        // survivable — an unnamed detection still tells the user something happened.
        "$meta=@{};",
        "try{foreach($t in @(Get-MpThreat -ErrorAction Stop))",
        "{if($null -ne $t.ThreatID){$meta[[string]$t.ThreatID]=$t}}}catch{};",
        "$items=@();",
        "foreach($d in @(Get-MpThreatDetection -ErrorAction Stop)){",
        "$when=$d.InitialDetectionTime;",
        "if($null -eq $when){$when=$d.LastThreatStatusChangeTime};",
        // Undateable, so it cannot be claimed as recent. Dropped rather than guessed at.
        "if($null -eq $when){continue};",
        "$when=[datetime]$when;",
        "if($when -lt $since){continue};",
        "$m=$meta[[string]$d.ThreatID];",
        "$items+=[pscustomobject]@{",
        "ThreatName=$(if($m){[string]$m.ThreatName}else{$null});",
        "SeverityId=$(if($m -and $null -ne $m.SeverityID){[int]$m.SeverityID}else{0});",
        "Resources=[string[]]@($d.Resources);",
        "DetectedUtc=$when.ToUniversalTime().ToString('o');",
        "ActionId=$(if($null -ne $d.CleaningActionID){[int]$d.CleaningActionID}else{0});",
        "StatusId=$(if($null -ne $d.ThreatStatusID){[int]$d.ThreatStatusID}else{0});",
        "ActionSucceeded=$(if($null -ne $d.ActionSuccess){[bool]$d.ActionSuccess}else{$null});",
        "ProcessName=[string]$d.ProcessName;",
        "}};",
        // [object[]] so a single detection still serialises as an array rather than a bare object.
        "[pscustomobject]@{Items=[object[]]$items}|ConvertTo-Json -Compress -Depth 4",
        "}catch{exit 3}");
}

/// <summary>
/// Whether Defender is the machine's actual antivirus. A third-party product pushes Defender into
/// passive mode, which is a perfectly healthy state and must never be reported as "unprotected".
/// </summary>
public enum DefenderRunningMode
{
    /// <summary>Defender did not say, or said something we do not recognise.</summary>
    Unknown = 0,

    /// <summary>Defender is the active antivirus.</summary>
    Normal = 1,

    /// <summary>Another antivirus is in charge; Defender is watching but not protecting.</summary>
    Passive = 2,

    /// <summary>Defender remediates for an EDR product but is not the primary antivirus.</summary>
    EdrBlock = 3,

    /// <summary>Defender is not running at all.</summary>
    NotRunning = 4,
}

/// <summary>Defender's own severity grading for a detection. The numbers are Defender's, not ours.</summary>
public enum DefenderThreatSeverity
{
    /// <summary>Defender did not grade it, or graded it with a value we do not recognise.</summary>
    Unknown = 0,

    /// <summary>Low.</summary>
    Low = 1,

    /// <summary>Moderate.</summary>
    Moderate = 2,

    /// <summary>High.</summary>
    High = 4,

    /// <summary>Severe.</summary>
    Severe = 5,
}

/// <summary>
/// Defender's state at one moment. Every field is optional because Defender genuinely does not
/// report all of them on every platform version, and a missing field must read as "unknown" rather
/// than as a negative answer.
/// </summary>
public sealed record DefenderSnapshot
{
    /// <summary>Whether Defender is the active antivirus, or standing aside for another product.</summary>
    public required DefenderRunningMode RunningMode { get; init; }

    /// <summary>Defender's own wording for <see cref="RunningMode"/>, kept for display and diagnosis.</summary>
    public string? RunningModeRaw { get; init; }

    /// <summary>Whether the antimalware service is running.</summary>
    public bool? ServiceEnabled { get; init; }

    /// <summary>Whether antivirus protection is enabled.</summary>
    public bool? AntivirusEnabled { get; init; }

    /// <summary>Whether real-time protection is enabled.</summary>
    public bool? RealTimeProtectionEnabled { get; init; }

    /// <summary>Whether behaviour monitoring is enabled.</summary>
    public bool? BehaviourMonitoringEnabled { get; init; }

    /// <summary>Whether tamper protection is on — the thing that stops malware turning Defender off.</summary>
    public bool? TamperProtectionEnabled { get; init; }

    /// <summary>Antivirus signature version, e.g. <c>1.455.439.0</c>.</summary>
    public string? SignatureVersion { get; init; }

    /// <summary>Age of the signatures in days, or <see langword="null"/> when Defender cannot say.</summary>
    public int? SignatureAgeDays { get; init; }

    /// <summary>When the signatures were last updated (UTC).</summary>
    public DateTimeOffset? SignatureLastUpdatedUtc { get; init; }

    /// <summary>When the last quick scan finished (UTC). Null means no quick scan is recorded.</summary>
    public DateTimeOffset? LastQuickScanUtc { get; init; }

    /// <summary>When the last full scan finished (UTC). Null means no full scan is recorded.</summary>
    public DateTimeOffset? LastFullScanUtc { get; init; }

    /// <summary>Defender's own opinion of whether its signatures are stale.</summary>
    public bool? SignaturesOutOfDate { get; init; }

    /// <summary>
    /// Every antivirus registered with Windows Security Center, Defender included. Empty when the
    /// list could not be read — which is normal on Server SKUs, and is not evidence of anything.
    /// </summary>
    public IReadOnlyList<string> RegisteredProviders { get; init; } = [];

    /// <summary>When this snapshot was taken (UTC), so the UI can say how fresh it is.</summary>
    public DateTimeOffset CapturedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Whether Defender is actually the thing protecting this machine.
    ///
    /// <para>
    /// <see langword="null"/> means we could not tell, and the UI must say so rather than assume.
    /// <see langword="false"/> does <b>not</b> mean the machine is unprotected — check
    /// <see cref="ThirdPartyProviderName"/> first, because the overwhelmingly common cause is
    /// another antivirus doing its job.
    /// </para>
    /// </summary>
    public bool? IsActiveProvider => RunningMode switch
    {
        DefenderRunningMode.Normal => true,
        DefenderRunningMode.Passive or DefenderRunningMode.EdrBlock or DefenderRunningMode.NotRunning => false,

        // Older platforms do not report a running mode at all, so fall back to the two flags that
        // have always been there — and only when both of them actually answered.
        _ => ServiceEnabled is { } service && AntivirusEnabled is { } antivirus
            ? service && antivirus
            : null,
    };

    /// <summary>
    /// The name of a non-Microsoft antivirus registered on this machine, if there is one. This is
    /// the difference between "your machine is unprotected" and "Norton is handling it", and getting
    /// that wrong is how a maintenance app frightens somebody for no reason.
    /// </summary>
    public string? ThirdPartyProviderName
    {
        get
        {
            foreach (var provider in RegisteredProviders)
            {
                if (IsMicrosoftProvider(provider)) continue;
                return provider;
            }

            return null;
        }
    }

    private static bool IsMicrosoftProvider(string name) =>
        name.StartsWith("Windows Defender", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Microsoft Defender", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// One entry from Defender's own detection history, reported as-is.
///
/// <para>
/// This is the one place in Ballast where words like "threat" and "quarantined" are allowed, because
/// they are quotations: Defender said them, about something Defender found, and it already acted.
/// Ballast is only the messenger and must never present its own heuristic findings in this
/// vocabulary.
/// </para>
/// </summary>
public sealed record DefenderDetection
{
    /// <summary>Defender's name for what it found, e.g. <c>Trojan:Win32/…</c>.</summary>
    public required string ThreatName { get; init; }

    /// <summary>Defender's severity grading.</summary>
    public required DefenderThreatSeverity Severity { get; init; }

    /// <summary>When Defender first saw it (UTC).</summary>
    public required DateTimeOffset DetectedUtc { get; init; }

    /// <summary>
    /// What Defender did about it, in plain language — or the raw status code when Defender reports
    /// one we do not have a documented label for.
    /// </summary>
    public required string ActionTaken { get; init; }

    /// <summary>Whether that action succeeded, when Defender reports it.</summary>
    public bool? ActionSucceeded { get; init; }

    /// <summary>The file involved, if the detection names one.</summary>
    public string? TargetPath { get; init; }

    /// <summary>
    /// Every resource Defender attached to the detection, prefixes intact
    /// (<c>file:_…</c>, <c>process:_…</c>, <c>regkey:_…</c>).
    /// </summary>
    public IReadOnlyList<string> Resources { get; init; } = [];

    /// <summary>The process Defender associated with the detection, when it recorded one.</summary>
    public string? ProcessName { get; init; }
}
