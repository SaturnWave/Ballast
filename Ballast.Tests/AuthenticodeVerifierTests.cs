using Ballast.Core.Security;
using Xunit;

namespace Ballast.Tests;

/// <summary>
/// The security feature's rules all lean on this one answer, so the tests care most about the two
/// ways it could mislead them: calling a legitimate signed program unsigned, and calling something
/// it could not read unsigned. Both would produce findings against a clean machine, which is the
/// failure mode this feature cannot afford.
///
/// <para>
/// Everything here runs against files Windows itself ships, so nothing depends on a third-party
/// program being installed.
/// </para>
/// </summary>
public class AuthenticodeVerifierTests : IDisposable
{
    private static readonly string WindowsDirectory =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private readonly AuthenticodeVerifier _verifier = new();
    private readonly List<string> _temporaryFiles = [];

    public void Dispose()
    {
        foreach (string path in _temporaryFiles)
        {
            try { File.Delete(path); } catch { /* a leftover temp file is not a test failure */ }
        }

        GC.SuppressFinalize(this);
    }

    private string CreateTemporaryFile(string extension, byte[] contents)
    {
        string path = Path.Combine(Path.GetTempPath(), $"Ballast-sig-{Guid.NewGuid():N}{extension}");
        File.WriteAllBytes(path, contents);
        _temporaryFiles.Add(path);
        return path;
    }

    private static string SystemFile(string relativePath) =>
        Path.Combine(WindowsDirectory, relativePath);

    // ---- Windows' own binaries ----

    /// <summary>
    /// The load-bearing case. <c>notepad.exe</c> in particular carries no embedded signature on a
    /// current Windows install — it is vouched for by a catalog under <c>CatRoot</c>. A verifier
    /// that only inspected embedded signatures would call it unsigned, and every rule built on
    /// this would then flag the operating system itself.
    /// </summary>
    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("explorer.exe")]
    public async Task Windows_binaries_verify_as_validly_signed_by_Microsoft(string name)
    {
        string path = SystemFile(name);
        Assert.True(File.Exists(path), $"{path} is missing, so this machine cannot run the test");

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.True(info.IsMicrosoft, $"{name} was not recognised as Microsoft-signed");
        Assert.Equal("Microsoft Corporation", info.SignerName);
    }

    [Fact]
    public async Task A_system_library_is_also_recognised()
    {
        SignatureInfo info = await _verifier.VerifyAsync(SystemFile(@"system32\kernel32.dll"));

        Assert.Equal(SignatureStatus.Valid, info.Status);
        Assert.True(info.IsMicrosoft);
    }

    // ---- Unsigned files ----

    [Fact]
    public async Task A_plain_text_file_is_unsigned()
    {
        string path = CreateTemporaryFile(".txt", "just text, not a program\n"u8.ToArray());

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Unsigned, info.Status);
        Assert.False(info.IsMicrosoft);
        Assert.Null(info.SignerName);
    }

    [Fact]
    public async Task An_unsigned_binary_is_unsigned_rather_than_unreadable()
    {
        string path = CreateTemporaryFile(".exe", new byte[4096]);

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Unsigned, info.Status);
        Assert.False(info.IsMicrosoft);
    }

    /// <summary>
    /// Unsigned must never imply Microsoft. This is the pairing a rule would use to decide a
    /// startup entry is worth mentioning, so the two flags must not drift apart.
    /// </summary>
    [Fact]
    public async Task An_unsigned_file_is_never_marked_as_Microsoft()
    {
        string path = CreateTemporaryFile(".exe", [0x4D, 0x5A, 0x90, 0x00]);

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.NotEqual(SignatureStatus.Valid, info.Status);
        Assert.False(info.IsMicrosoft);
    }

    // ---- Paths that cannot be verified ----

    /// <summary>
    /// Every one of these must be <see cref="SignatureStatus.Unreadable"/> and none may throw.
    /// Unreadable is deliberately not a milder Unsigned: a rule that fires on "unsigned" must stay
    /// silent for a path we never managed to look at.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("notepad.exe")]                       // relative, would resolve against our own cwd
    [InlineData(@"\\somehost\share\program.exe")]     // UNC: a dead share would block the scan
    [InlineData(@"\\?\C:\Windows\notepad.exe")]       // device-path form
    [InlineData("<<<not a path>>>")]
    [InlineData(@"C:\this-directory-does-not-exist-9f3a\nothing.exe")]
    public async Task Paths_that_cannot_be_verified_are_unreadable_and_do_not_throw(string? path)
    {
        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Unreadable, info.Status);
        Assert.False(info.IsMicrosoft);
        Assert.Null(info.SignerName);
    }

    [Fact]
    public async Task A_missing_file_in_a_real_directory_is_unreadable()
    {
        SignatureInfo info = await _verifier.VerifyAsync(SystemFile("no-such-program-4a91c.exe"));

        Assert.Equal(SignatureStatus.Unreadable, info.Status);
    }

    [Fact]
    public async Task A_directory_is_unreadable_rather_than_unsigned()
    {
        // A caller with an unresolved command line can easily hand us a folder.
        SignatureInfo info = await _verifier.VerifyAsync(WindowsDirectory);

        Assert.Equal(SignatureStatus.Unreadable, info.Status);
    }

    /// <summary>
    /// A file another process holds exclusively cannot be hashed, so no catalog lookup is possible
    /// and no claim about its signature is justified.
    /// </summary>
    [Fact]
    public async Task A_file_locked_by_another_handle_is_unreadable()
    {
        string path = CreateTemporaryFile(".exe", new byte[2048]);

        using FileStream exclusive = new(path, FileMode.Open, FileAccess.Read, FileShare.None);

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Unreadable, info.Status);
        Assert.False(info.IsMicrosoft);
    }

    // ---- Behaviour the callers depend on ----

    [Fact]
    public async Task A_cancelled_verification_yields_unreadable_instead_of_throwing()
    {
        using CancellationTokenSource cts = new();
        cts.Cancel();

        SignatureInfo info = await _verifier.VerifyAsync(SystemFile("explorer.exe"), cts.Token);

        Assert.Equal(SignatureStatus.Unreadable, info.Status);
    }

    /// <summary>
    /// A cancelled call must not poison the cache — the next caller has to get a real answer.
    /// </summary>
    [Fact]
    public async Task Cancelling_one_call_does_not_cache_the_non_answer()
    {
        string path = SystemFile("explorer.exe");

        using (CancellationTokenSource cts = new())
        {
            cts.Cancel();
            await _verifier.VerifyAsync(path, cts.Token);
        }

        SignatureInfo info = await _verifier.VerifyAsync(path);

        Assert.Equal(SignatureStatus.Valid, info.Status);
    }

    [Fact]
    public async Task Repeated_verification_of_the_same_file_agrees_with_itself()
    {
        string path = SystemFile("explorer.exe");

        SignatureInfo first = await _verifier.VerifyAsync(path);
        SignatureInfo second = await _verifier.VerifyAsync(path);

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task Clearing_the_cache_still_produces_the_same_answer()
    {
        string path = SystemFile("explorer.exe");

        SignatureInfo before = await _verifier.VerifyAsync(path);
        _verifier.ClearCache();
        SignatureInfo after = await _verifier.VerifyAsync(path);

        Assert.Equal(before, after);
    }

    /// <summary>
    /// The same path is normalised to the same cache entry however it is written, so a scan does
    /// not re-verify a file because one rule spelled it differently.
    /// </summary>
    [Fact]
    public async Task Equivalent_spellings_of_a_path_give_the_same_answer()
    {
        string canonical = SystemFile(@"system32\kernel32.dll");
        string quoted = $"\"{canonical}\"";
        string viaEnvironmentVariable = @"%WINDIR%\system32\kernel32.dll";
        string withRedundantSegment = SystemFile(@"system32\..\system32\kernel32.dll");

        SignatureInfo expected = await _verifier.VerifyAsync(canonical);

        Assert.Equal(expected, await _verifier.VerifyAsync(quoted));
        Assert.Equal(expected, await _verifier.VerifyAsync(viaEnvironmentVariable));
        Assert.Equal(expected, await _verifier.VerifyAsync(withRedundantSegment));
    }

    /// <summary>
    /// A scan verifies from several threads at once. Concurrent callers must all get the same
    /// answer and none may see a torn or half-built result.
    /// </summary>
    [Fact]
    public async Task Concurrent_verification_is_safe_and_consistent()
    {
        string[] paths =
        [
            SystemFile("explorer.exe"),
            SystemFile("notepad.exe"),
            SystemFile(@"system32\kernel32.dll"),
            CreateTemporaryFile(".exe", new byte[512]),
        ];

        SignatureInfo[] results = await Task.WhenAll(
            Enumerable.Range(0, 120).Select(i => _verifier.VerifyAsync(paths[i % paths.Length])));

        for (int i = 0; i < results.Length; i++)
        {
            Assert.Equal(await _verifier.VerifyAsync(paths[i % paths.Length]), results[i]);
        }

        // The three Windows binaries must all have verified; only the planted file is unsigned.
        Assert.Equal(30, results.Count(r => r.Status == SignatureStatus.Unsigned));
        Assert.Equal(90, results.Count(r => r.Status == SignatureStatus.Valid));
    }

    [Fact]
    public async Task The_shared_instance_works_and_agrees_with_a_fresh_one()
    {
        string path = SystemFile("explorer.exe");

        Assert.Equal(await _verifier.VerifyAsync(path), await AuthenticodeVerifier.Shared.VerifyAsync(path));
    }

    /// <summary>
    /// A verification that blocked on a CRL fetch over a dead network would freeze the whole scan.
    /// Cache-only revocation retrieval is what prevents that, and this is its regression guard.
    /// </summary>
    [Fact]
    public async Task Verification_completes_promptly_and_never_waits_on_the_network()
    {
        Task<SignatureInfo> pending = _verifier.VerifyAsync(SystemFile("explorer.exe"));

        Task first = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(30)));

        Assert.Same(pending, first);
        Assert.Equal(SignatureStatus.Valid, (await pending).Status);
    }

    // ---- The honesty line ----

    /// <summary>
    /// Nothing in this class may read as a verdict. It reports what a signature says; deciding
    /// whether software is malicious is Windows Defender's job, and the vocabulary has to keep
    /// that distinction visible.
    /// </summary>
    [Fact]
    public void The_status_vocabulary_makes_no_accusation()
    {
        string[] names = Enum.GetNames<SignatureStatus>();

        Assert.DoesNotContain(names, n =>
            n.Contains("Virus", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Malware", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Threat", StringComparison.OrdinalIgnoreCase) ||
            n.Contains("Infected", StringComparison.OrdinalIgnoreCase));
    }
}
