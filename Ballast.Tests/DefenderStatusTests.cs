using System.Reflection;
using Ballast.Core.Security;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Covers Ballast's read-only view of Microsoft Defender.
///
/// <para>
/// None of these tests assume Defender is installed, enabled, or in any particular state — that
/// assumption is exactly what breaks on a Server SKU, on a machine running a third-party antivirus,
/// or on a build image with Defender stripped out. The parsing tests therefore run entirely against
/// captured JSON, and the few tests that touch the real machine only assert that nothing throws and
/// that whatever comes back is internally coherent.
/// </para>
///
/// <para>
/// No test starts a real scan. The only scan behaviour exercised here is the refusal.
/// </para>
/// </summary>
public sealed class DefenderStatusTests
{
    /// <summary>
    /// Captured verbatim from <c>Get-MpComputerStatus</c> on a healthy Windows 11 machine with
    /// Defender active and no full scan ever run.
    /// </summary>
    private const string HealthyStatusJson = """
        {"RunningMode":"Normal","ServiceEnabled":true,"AntivirusEnabled":true,
        "RealTimeProtectionEnabled":true,"BehaviorMonitorEnabled":true,"TamperProtected":true,
        "SignatureVersion":"1.455.447.0","SignatureAgeDays":"0",
        "SignatureLastUpdated":"2026-07-31T18:17:30.0000000Z",
        "LastQuickScan":"2026-07-31T12:20:05.2130000Z","LastFullScan":null,
        "SignaturesOutOfDate":false,"RegisteredProviders":["Windows Defender"]}
        """;

    // ---------------------------------------------------------------- status parsing

    [Fact]
    public void A_captured_status_document_produces_the_fields_it_describes()
    {
        var snapshot = DefenderStatus.ParseStatusJson(HealthyStatusJson);

        Assert.NotNull(snapshot);
        Assert.Equal(DefenderRunningMode.Normal, snapshot!.RunningMode);
        Assert.Equal("Normal", snapshot.RunningModeRaw);
        Assert.True(snapshot.ServiceEnabled);
        Assert.True(snapshot.AntivirusEnabled);
        Assert.True(snapshot.RealTimeProtectionEnabled);
        Assert.True(snapshot.BehaviourMonitoringEnabled);
        Assert.True(snapshot.TamperProtectionEnabled);
        Assert.Equal("1.455.447.0", snapshot.SignatureVersion);
        Assert.Equal(0, snapshot.SignatureAgeDays);
        Assert.False(snapshot.SignaturesOutOfDate);
        Assert.True(snapshot.IsActiveProvider);

        Assert.Equal(
            new DateTimeOffset(2026, 7, 31, 18, 17, 30, TimeSpan.Zero),
            snapshot.SignatureLastUpdatedUtc);

        Assert.Equal(
            new DateTimeOffset(2026, 7, 31, 12, 20, 5, 213, TimeSpan.Zero),
            snapshot.LastQuickScanUtc);

        Assert.Equal(new[] { "Windows Defender" }, snapshot.RegisteredProviders);
    }

    [Fact]
    public void A_full_scan_that_never_ran_is_no_date_rather_than_a_wrong_one()
    {
        var snapshot = DefenderStatus.ParseStatusJson(HealthyStatusJson);

        Assert.NotNull(snapshot);
        Assert.Null(snapshot!.LastFullScanUtc);
    }

    /// <summary>
    /// The headline false-positive risk of this whole feature: a machine with Norton installed has
    /// Defender in passive mode, which is healthy. Ballast must be able to say "another antivirus is
    /// handling it" rather than "you are unprotected".
    /// </summary>
    [Fact]
    public void Passive_mode_names_the_antivirus_that_is_actually_in_charge()
    {
        const string json = """
            {"RunningMode":"Passive","ServiceEnabled":true,"AntivirusEnabled":false,
            "RealTimeProtectionEnabled":false,
            "RegisteredProviders":["Windows Defender","Norton 360"]}
            """;

        var snapshot = DefenderStatus.ParseStatusJson(json);

        Assert.NotNull(snapshot);
        Assert.Equal(DefenderRunningMode.Passive, snapshot!.RunningMode);
        Assert.False(snapshot.IsActiveProvider);
        Assert.Equal("Norton 360", snapshot.ThirdPartyProviderName);
    }

    [Theory]
    [InlineData("SxS Passive Mode", DefenderRunningMode.Passive)]
    [InlineData("EDR Block Mode", DefenderRunningMode.EdrBlock)]
    [InlineData("Not running", DefenderRunningMode.NotRunning)]
    [InlineData("Normal", DefenderRunningMode.Normal)]
    [InlineData("something Microsoft has not shipped yet", DefenderRunningMode.Unknown)]
    public void Every_documented_running_mode_wording_is_recognised(string raw, DefenderRunningMode expected)
    {
        var snapshot = DefenderStatus.ParseStatusJson($$"""{"RunningMode":"{{raw}}"}""");

        Assert.NotNull(snapshot);
        Assert.Equal(expected, snapshot!.RunningMode);
    }

    [Theory]
    [InlineData("Windows Defender")]
    [InlineData("Microsoft Defender Antivirus")]
    [InlineData("windows defender")]
    public void Defender_itself_is_never_mistaken_for_a_third_party_product(string provider)
    {
        var snapshot = DefenderStatus.ParseStatusJson(
            $$"""{"RunningMode":"Normal","RegisteredProviders":["{{provider}}"]}""");

        Assert.NotNull(snapshot);
        Assert.Null(snapshot!.ThirdPartyProviderName);
    }

    /// <summary>
    /// Older Defender platforms do not report every flag. An absent flag has to read as "unknown",
    /// because rendering it as <c>false</c> would put "real-time protection: off" on the screen of a
    /// perfectly protected machine.
    /// </summary>
    [Fact]
    public void A_flag_defender_did_not_report_is_unknown_rather_than_off()
    {
        var snapshot = DefenderStatus.ParseStatusJson("""{"RunningMode":"Normal","SignatureVersion":"1.1.1.1"}""");

        Assert.NotNull(snapshot);
        Assert.Null(snapshot!.RealTimeProtectionEnabled);
        Assert.Null(snapshot.TamperProtectionEnabled);
        Assert.Null(snapshot.AntivirusEnabled);
        Assert.Null(snapshot.SignatureAgeDays);
        Assert.Empty(snapshot.RegisteredProviders);
    }

    [Fact]
    public void Without_a_running_mode_the_old_flags_decide()
    {
        var enabled = DefenderStatus.ParseStatusJson("""{"ServiceEnabled":true,"AntivirusEnabled":true}""");
        var disabled = DefenderStatus.ParseStatusJson("""{"ServiceEnabled":true,"AntivirusEnabled":false}""");

        Assert.NotNull(enabled);
        Assert.NotNull(disabled);
        Assert.True(enabled!.IsActiveProvider);
        Assert.False(disabled!.IsActiveProvider);
    }

    [Fact]
    public void With_neither_a_running_mode_nor_the_flags_we_admit_we_cannot_tell()
    {
        var snapshot = DefenderStatus.ParseStatusJson("""{"SignatureVersion":"1.1.1.1"}""");

        Assert.NotNull(snapshot);
        Assert.Equal(DefenderRunningMode.Unknown, snapshot!.RunningMode);
        Assert.Null(snapshot.IsActiveProvider);
    }

    /// <summary>
    /// Windows PowerShell serialises the result of an <c>if</c> with no <c>else</c> as <c>{}</c>,
    /// not as <c>null</c>. That was observed for real while building this, and an object arriving
    /// where a date was expected must not become an exception or a bogus timestamp.
    /// </summary>
    [Fact]
    public void An_absent_value_serialised_as_an_empty_object_does_not_become_a_date()
    {
        var snapshot = DefenderStatus.ParseStatusJson(
            """{"RunningMode":"Normal","LastQuickScan":{},"LastFullScan":{},"TamperProtected":{}}""");

        Assert.NotNull(snapshot);
        Assert.Null(snapshot!.LastQuickScanUtc);
        Assert.Null(snapshot.LastFullScanUtc);
        Assert.Null(snapshot.TamperProtectionEnabled);
    }

    /// <summary>
    /// Defender reports an unknown age as <c>UInt32.MaxValue</c>. Printing that literally would tell
    /// the user their signatures are eleven million days old.
    /// </summary>
    [Theory]
    [InlineData("4294967295")]
    [InlineData("-1")]
    [InlineData("99999")]
    [InlineData("not a number")]
    public void A_nonsensical_signature_age_is_reported_as_unknown(string age)
    {
        var snapshot = DefenderStatus.ParseStatusJson(
            $$"""{"RunningMode":"Normal","SignatureAgeDays":"{{age}}"}""");

        Assert.NotNull(snapshot);
        Assert.Null(snapshot!.SignatureAgeDays);
    }

    [Fact]
    public void A_plausible_signature_age_survives_as_a_number()
    {
        var fromString = DefenderStatus.ParseStatusJson("""{"SignatureAgeDays":"3"}""");
        var fromNumber = DefenderStatus.ParseStatusJson("""{"SignatureAgeDays":3}""");

        Assert.NotNull(fromString);
        Assert.NotNull(fromNumber);
        Assert.Equal(3, fromString!.SignatureAgeDays);
        Assert.Equal(3, fromNumber!.SignatureAgeDays);
    }

    /// <summary>
    /// The scripts normalise dates to round-trip UTC, but the raw Windows PowerShell form is still
    /// understood so that a host which stops normalising does not silently lose every timestamp.
    /// </summary>
    [Fact]
    public void The_raw_windows_powershell_date_format_is_still_understood()
    {
        var snapshot = DefenderStatus.ParseStatusJson(
            """{"RunningMode":"Normal","LastQuickScan":"\/Date(1785476727000)\/"}""");

        Assert.NotNull(snapshot);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1785476727000), snapshot!.LastQuickScanUtc);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    [InlineData("{")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("42")]
    [InlineData("\"a bare string\"")]
    [InlineData("INFO: the Defender module is not installed on this machine.")]
    public void Unreadable_status_output_yields_no_snapshot_and_no_exception(string json)
        => Assert.Null(DefenderStatus.ParseStatusJson(json));

    // ---------------------------------------------------------------- detection parsing

    [Fact]
    public void An_empty_detection_history_is_an_empty_list()
        => Assert.Empty(DefenderStatus.ParseDetectionsJson("""{"Items":[]}"""));

    [Fact]
    public void A_detection_is_reported_in_defenders_own_terms()
    {
        const string json = """
            {"Items":[{"ThreatName":"Trojan:Win32/Wacatac.B!ml","SeverityId":5,
            "Resources":["file:_C:\\Users\\sam\\Downloads\\keygen.exe"],
            "DetectedUtc":"2026-07-20T09:15:00.0000000Z","ActionId":2,"StatusId":3,
            "ActionSucceeded":true,"ProcessName":"Unknown"}]}
            """;

        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(json));

        Assert.Equal("Trojan:Win32/Wacatac.B!ml", detection.ThreatName);
        Assert.Equal(DefenderThreatSeverity.Severe, detection.Severity);
        Assert.Equal("Quarantined", detection.ActionTaken);
        Assert.True(detection.ActionSucceeded);
        Assert.Equal(@"C:\Users\sam\Downloads\keygen.exe", detection.TargetPath);
        Assert.Equal(new DateTimeOffset(2026, 7, 20, 9, 15, 0, TimeSpan.Zero), detection.DetectedUtc);
    }

    [Theory]
    [InlineData(1, DefenderThreatSeverity.Low)]
    [InlineData(2, DefenderThreatSeverity.Moderate)]
    [InlineData(4, DefenderThreatSeverity.High)]
    [InlineData(5, DefenderThreatSeverity.Severe)]
    [InlineData(0, DefenderThreatSeverity.Unknown)]
    [InlineData(77, DefenderThreatSeverity.Unknown)]
    public void Defenders_severity_numbers_map_to_defenders_severity_names(
        int severityId,
        DefenderThreatSeverity expected)
    {
        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(
            $$"""{"Items":[{"SeverityId":{{severityId}},"DetectedUtc":"2026-07-20T09:15:00Z"}]}"""));

        Assert.Equal(expected, detection.Severity);
    }

    [Theory]
    [InlineData(2, "Cleaned")]
    [InlineData(3, "Quarantined")]
    [InlineData(4, "Removed")]
    [InlineData(5, "Allowed")]
    [InlineData(6, "Blocked")]
    public void Documented_status_codes_get_their_documented_words(int statusId, string expected)
    {
        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(
            $$"""{"Items":[{"StatusId":{{statusId}},"DetectedUtc":"2026-07-20T09:15:00Z"}]}"""));

        Assert.Equal(expected, detection.ActionTaken);
    }

    /// <summary>
    /// Guessing a label for a status code we have no documentation for would put words in Defender's
    /// mouth — and "Removed" is not a word to guess at, because a user who reads it stops looking for
    /// the file.
    /// </summary>
    [Fact]
    public void An_undocumented_status_code_is_shown_as_a_code_not_invented()
    {
        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(
            """{"Items":[{"StatusId":107,"DetectedUtc":"2026-07-20T09:15:00Z"}]}"""));

        Assert.Contains("107", detection.ActionTaken, StringComparison.Ordinal);
        Assert.DoesNotContain("Removed", detection.ActionTaken, StringComparison.Ordinal);
        Assert.DoesNotContain("Quarantined", detection.ActionTaken, StringComparison.Ordinal);
    }

    [Fact]
    public void A_detection_with_no_recorded_status_falls_back_to_the_cleaning_action()
    {
        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(
            """{"Items":[{"StatusId":1,"ActionId":10,"DetectedUtc":"2026-07-20T09:15:00Z"}]}"""));

        Assert.Equal("Blocked", detection.ActionTaken);
    }

    [Fact]
    public void A_detection_defender_did_not_name_still_gets_a_neutral_label()
    {
        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(
            """{"Items":[{"DetectedUtc":"2026-07-20T09:15:00Z"}]}"""));

        Assert.False(string.IsNullOrWhiteSpace(detection.ThreatName));
        Assert.Null(detection.TargetPath);
    }

    /// <summary>
    /// A "recent detections" list cannot honestly contain an entry nobody can date, so an undateable
    /// record is dropped rather than shown with a made-up time.
    /// </summary>
    [Fact]
    public void A_detection_that_cannot_be_dated_is_left_out()
    {
        const string json = """
            {"Items":[{"ThreatName":"A","DetectedUtc":null},
            {"ThreatName":"B"},
            {"ThreatName":"C","DetectedUtc":{}},
            {"ThreatName":"D","DetectedUtc":"2026-07-20T09:15:00Z"}]}
            """;

        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(json));
        Assert.Equal("D", detection.ThreatName);
    }

    /// <summary>
    /// A registry key or a process id shown in a field labelled as a file path is a lie the UI would
    /// repeat faithfully, so only file resources are promoted to a path.
    /// </summary>
    [Fact]
    public void Only_a_file_resource_becomes_a_target_path()
    {
        const string json = """
            {"Items":[{"DetectedUtc":"2026-07-20T09:15:00Z",
            "Resources":["process:_pid:4128","regkey:_HKLM\\Software\\Bad","webfile:_https://x.test/a"]}]}
            """;

        var detection = Assert.Single(DefenderStatus.ParseDetectionsJson(json));

        Assert.Null(detection.TargetPath);
        Assert.Equal(3, detection.Resources.Count);
    }

    [Fact]
    public void Detections_come_back_newest_first()
    {
        const string json = """
            {"Items":[{"ThreatName":"older","DetectedUtc":"2026-07-01T09:00:00Z"},
            {"ThreatName":"newest","DetectedUtc":"2026-07-28T09:00:00Z"},
            {"ThreatName":"middle","DetectedUtc":"2026-07-14T09:00:00Z"}]}
            """;

        var names = DefenderStatus.ParseDetectionsJson(json).Select(d => d.ThreatName).ToArray();

        Assert.Equal(new[] { "newest", "middle", "older" }, names);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("""{"Items":null}""")]
    [InlineData("""{"Items":"nope"}""")]
    [InlineData("""{"Items":[null,4,"x"]}""")]
    public void Unreadable_detection_output_yields_an_empty_list_and_no_exception(string json)
        => Assert.Empty(DefenderStatus.ParseDetectionsJson(json));

    // ---------------------------------------------------------------- Defender unavailable

    /// <summary>A host that is not there stands in for Defender being absent entirely.</summary>
    private static DefenderStatus WithMissingHost() => new()
    {
        PowerShellPath = Path.Combine(
            Path.GetTempPath(), "Ballast-no-such-host-" + Guid.NewGuid().ToString("N") + ".exe"),
    };

    /// <summary>
    /// A host that starts and exits promptly but answers with something that is not JSON — which is
    /// what a machine whose <c>Get-MpComputerStatus</c> is missing actually looks like from here.
    /// </summary>
    private static DefenderStatus WithUnhelpfulHost() => new()
    {
        PowerShellPath = Path.Combine(Environment.SystemDirectory, "whoami.exe"),
    };

    [Fact]
    public async Task A_missing_powershell_host_yields_no_snapshot_rather_than_an_exception()
        => Assert.Null(await WithMissingHost().GetAsync());

    [Fact]
    public async Task A_host_that_does_not_answer_in_json_yields_no_snapshot()
        => Assert.Null(await WithUnhelpfulHost().GetAsync());

    [Fact]
    public async Task A_missing_powershell_host_yields_an_empty_detection_list()
        => Assert.Empty(await WithMissingHost().GetRecentDetectionsAsync());

    [Fact]
    public async Task A_host_that_does_not_answer_in_json_yields_an_empty_detection_list()
        => Assert.Empty(await WithUnhelpfulHost().GetRecentDetectionsAsync());

    [Fact]
    public async Task An_already_cancelled_read_returns_nothing_rather_than_throwing()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        Assert.Null(await new DefenderStatus().GetAsync(cancelled.Token));
        Assert.Empty(await new DefenderStatus().GetRecentDetectionsAsync(30, cancelled.Token));
    }

    // ---------------------------------------------------------------- this machine, whatever it is

    /// <summary>
    /// Deliberately asserts almost nothing about the result: this has to pass on a machine with
    /// Defender active, on one running Norton, and on one where the cmdlet does not exist at all.
    /// What it does prove is that the real process plumbing runs to completion and hands back
    /// something coherent rather than throwing or hanging.
    /// </summary>
    [Fact]
    public async Task Reading_the_real_defender_state_never_throws()
    {
        var snapshot = await new DefenderStatus().GetAsync();

        if (snapshot is null) return;

        Assert.InRange(
            snapshot.CapturedAtUtc,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddMinutes(5));

        // Whatever the mode is, the derived answer must agree with it rather than contradict it.
        if (snapshot.RunningMode == DefenderRunningMode.Normal) Assert.True(snapshot.IsActiveProvider);
        if (snapshot.RunningMode == DefenderRunningMode.Passive) Assert.False(snapshot.IsActiveProvider);

        Assert.All(snapshot.RegisteredProviders, p => Assert.False(string.IsNullOrWhiteSpace(p)));
    }

    [Fact]
    public async Task Reading_the_real_detection_history_never_throws()
    {
        var detections = await new DefenderStatus().GetRecentDetectionsAsync(30);

        Assert.All(detections, d =>
        {
            Assert.False(string.IsNullOrWhiteSpace(d.ThreatName));
            Assert.False(string.IsNullOrWhiteSpace(d.ActionTaken));

            // The script filters by the window; a record outside it means the filter is broken.
            Assert.True(d.DetectedUtc > DateTimeOffset.UtcNow.AddDays(-40));
        });
    }

    [Fact]
    public void Resolving_mpcmdrun_gives_a_real_file_or_nothing_at_all()
    {
        var path = DefenderStatus.ResolveMpCmdRunPath();

        if (path is null) return;

        Assert.True(File.Exists(path));
        Assert.Equal("MpCmdRun.exe", Path.GetFileName(path));
    }

    // ---------------------------------------------------------------- refusals

    /// <summary>
    /// The only test that goes near <see cref="DefenderStatus.StartScanAsync"/>, and it exercises the
    /// refusal: a path that does not exist is rejected before anything is launched, so this cannot
    /// start a real scan even on a machine with Defender fully active.
    /// </summary>
    [Fact]
    public async Task A_scan_is_refused_for_a_path_that_does_not_exist()
    {
        var nowhere = Path.Combine(
            Path.GetTempPath(), "Ballast-no-such-folder-" + Guid.NewGuid().ToString("N"), "nothing.bin");

        Assert.False(File.Exists(nowhere));
        Assert.False(Directory.Exists(nowhere));

        Assert.False(await new DefenderStatus().StartScanAsync(nowhere));
    }

    /// <summary>
    /// Ballast reads Defender's mind; it does not drive it. This asserts that promise against the
    /// actual public surface, so a later well-meaning addition of "just a little" remediation has to
    /// delete a test that says why it must not exist.
    ///
    /// <para>
    /// Starting a scan is the single exception, and it is a request Defender handles under its own
    /// policy — not Ballast reaching into quarantine, exclusions or protection settings.
    /// </para>
    /// </summary>
    [Fact]
    public void Nothing_on_this_type_can_change_defenders_configuration()
    {
        string[] forbidden =
        [
            "disable", "remove", "delete", "quarantine", "release", "restore",
            "exclusion", "exclude", "preference", "unregister", "submit",
        ];

        var members = typeof(DefenderStatus)
            .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .ToArray();

        var offenders = members
            .Where(name => forbidden.Any(f => name.Contains(f, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        Assert.Empty(offenders);

        // And the one call that asks Defender to do anything stays what its name says it is.
        Assert.Contains(nameof(DefenderStatus.StartScanAsync), members);
    }
}
