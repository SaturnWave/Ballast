using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Ballast.Core.Util;

namespace Ballast.Core.Security;

/// <summary>
/// Outcome of an Authenticode check on one file.
/// </summary>
/// <remarks>
/// These are deliberately coarse. The security rules branch on them, and a finer-grained
/// vocabulary would tempt a rule into a judgement the evidence does not support.
/// </remarks>
public enum SignatureStatus
{
    /// <summary>No Authenticode signature at all — neither embedded nor in a Windows catalog.</summary>
    Unsigned,

    /// <summary>Signed, the digest matches, and the chain reached a trusted root.</summary>
    Valid,

    /// <summary>Signed and trusted, but the signing certificate is outside its validity window.</summary>
    Expired,

    /// <summary>
    /// Signed, but the signature does not hold: an untrusted root, a broken chain, an explicitly
    /// distrusted publisher, or a digest that no longer matches the file's contents.
    /// </summary>
    Untrusted,

    /// <summary>The signing certificate is listed as revoked by a cached revocation list.</summary>
    Revoked,

    /// <summary>
    /// No answer could be obtained. A missing file, a locked file, a cloud placeholder, a network
    /// path, or any unexpected failure.
    ///
    /// <para>
    /// This is not a milder form of <see cref="Unsigned"/> and must never be treated as one.
    /// "Cannot tell" means a rule stays silent — the same principle the deletion guards use.
    /// </para>
    /// </summary>
    Unreadable,
}

/// <summary>
/// What the verifier learned about one file's signature.
/// </summary>
/// <param name="Status">The trust outcome.</param>
/// <param name="SignerName">
/// Human-readable publisher, preferring the certificate's organisation over its common name.
/// <see langword="null"/> when the file is unsigned or the signer could not be read.
/// </param>
/// <param name="IsMicrosoft">
/// True only when the signature verified <em>and</em> the signer is Microsoft Corporation. Rules
/// use this to stay off Windows' own binaries; see <see cref="AuthenticodeVerifier"/> for why the
/// trust gate is part of the definition.
/// </param>
public sealed record SignatureInfo(SignatureStatus Status, string? SignerName, bool IsMicrosoft);

/// <summary>
/// Answers "is this file signed, and by whom" using the same machinery Windows itself uses:
/// <c>WinVerifyTrust</c> with <c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c>.
///
/// <para>
/// This is the highest-signal input the security feature has. It is not a malware detector and
/// makes no claim to be one — an unsigned binary is a perfectly ordinary thing, and the only
/// honest statement this class produces is a description of the signature, never a verdict.
/// </para>
///
/// <para><b>Both signing forms are checked, in this order:</b></para>
/// <list type="number">
/// <item><b>Embedded.</b> The signature carried inside the file. This is how nearly all
/// third-party software is signed.</item>
/// <item><b>Catalog.</b> A detached signature in a <c>.cat</c> file under
/// <c>%WINDIR%\System32\CatRoot</c>, matched by file hash. Checking this is not optional:
/// <c>notepad.exe</c>, <c>explorer.exe</c> and <c>kernel32.dll</c> on a current Windows 10/11
/// install carry <em>no</em> embedded signature and are catalog-signed only. A verifier that
/// skipped catalogs would report every Windows binary as <see cref="SignatureStatus.Unsigned"/>,
/// and the rules built on top would flag the entire operating system.</item>
/// </list>
///
/// <para><b>Why the call can never hang.</b> Verification asks for revocation checking across the
/// whole chain, but with <c>WTD_CACHE_ONLY_URL_RETRIEVAL</c>, so a CRL is consulted only if it is
/// already in the local cache. Without that flag a machine with a dead or captive network would
/// block on an HTTP fetch for every file in the scan. When revocation cannot be determined the
/// result falls back to the trust outcome rather than becoming an accusation.</para>
///
/// <para><b>Why nothing here throws.</b> A scan verifies hundreds of files that the app does not
/// control: files deleted mid-scan, files held open by another process, dehydrated cloud
/// placeholders, paths on a disconnected share. Every one of those is an
/// <see cref="SignatureStatus.Unreadable"/>, not an exception, so no caller needs a try block.</para>
/// </summary>
public sealed class AuthenticodeVerifier
{
    /// <summary>
    /// Ceiling on cached entries. A scan looks at hundreds of files, not hundreds of thousands;
    /// the cap only exists so a pathological caller cannot grow this without bound.
    /// </summary>
    private const int MaxCacheEntries = 4096;

    /// <summary>
    /// Results keyed by normalised full path. Concurrent because a scan verifies from several
    /// threads, and cached because <c>WinVerifyTrust</c> costs milliseconds per file — enough to
    /// dominate a scan that re-checks the same binary for several rules.
    /// </summary>
    private readonly ConcurrentDictionary<string, SignatureInfo> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Shared instance, so the cache lives for the process rather than for one scan. Thread-safe.
    /// </summary>
    public static AuthenticodeVerifier Shared { get; } = new();

    /// <summary>
    /// Verifies the Authenticode signature of <paramref name="filePath"/>.
    /// </summary>
    /// <param name="filePath">
    /// Path to a local file. May be <see langword="null"/> or blank: callers commonly hold an
    /// unresolved command line (<c>StartupEntry.ExecutablePath</c> is nullable), and that is not
    /// an error worth branching on at every call site.
    /// </param>
    /// <param name="ct">
    /// Cancels the verification. A cancelled call yields <see cref="SignatureStatus.Unreadable"/>
    /// rather than throwing, and its result is not cached.
    /// </param>
    /// <returns>
    /// A description of the signature. Never <see langword="null"/>, and this method never throws.
    /// </returns>
    public async Task<SignatureInfo> VerifyAsync(string? filePath, CancellationToken ct = default)
    {
        string? path = Normalise(filePath);
        if (path is null) return Unreadable;

        if (_cache.TryGetValue(path, out SignatureInfo? cached)) return cached;

        SignatureInfo info;

        try
        {
            // Off the calling thread without exception: this opens files, hashes them and calls
            // into wintrust. That is fine work for a thread pool thread and completely wrong work
            // for the UI thread.
            info = await Task.Run(() => Verify(path), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // A cancelled scan has no opinion about this file, and caching "no opinion" would
            // poison every later lookup of the same path.
            return Unreadable;
        }

        if (_cache.Count < MaxCacheEntries) _cache[path] = info;

        return info;
    }

    /// <summary>Empties the cache. Only useful in tests.</summary>
    public void ClearCache() => _cache.Clear();

    private static SignatureInfo Unreadable { get; } =
        new(SignatureStatus.Unreadable, null, false);

    private static SignatureInfo UnsignedInfo { get; } =
        new(SignatureStatus.Unsigned, null, false);

    /// <summary>
    /// Turns a raw path into a full local path, or <see langword="null"/> when it is not something
    /// worth verifying.
    /// </summary>
    private static string? Normalise(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;

        try
        {
            string trimmed = path.Trim().Trim('"').Trim();
            if (trimmed.Length == 0) return null;

            trimmed = Environment.ExpandEnvironmentVariables(trimmed).Trim();
            if (trimmed.Length == 0) return null;

            // A relative path would silently resolve against this process's working directory,
            // which has nothing to do with the program being described.
            if (!Path.IsPathFullyQualified(trimmed)) return null;

            // UNC shares, administrative shares and device paths all start this way. Verifying
            // across one means hashing the whole file over the wire.
            if (trimmed.StartsWith(@"\\", StringComparison.Ordinal)) return null;

            string full = Path.GetFullPath(trimmed);

            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrEmpty(root)) return null;
            if (root.StartsWith(@"\\", StringComparison.Ordinal)) return null;

            // A mapped network drive looks local until you read from it.
            DriveInfo drive = new(root);
            if (drive.DriveType is DriveType.Network or DriveType.NoRootDirectory) return null;

            return full;
        }
        catch
        {
            // Illegal characters, a path longer than the OS accepts, a drive that is not there.
            return null;
        }
    }

    /// <summary>The whole native path, wrapped so that no failure can escape.</summary>
    private static SignatureInfo Verify(string path)
    {
        try
        {
            FileInfo file = new(path);
            if (!file.Exists) return Unreadable;

            // Checked before the file is opened, and deliberately so: hashing a dehydrated
            // placeholder would make the sync client download the entire thing. A cloud file we
            // have not got locally is something we cannot tell about, not something unsigned.
            if (CloudFiles.IsPlaceholder(file)) return Unreadable;

            // The embedded signature first: it is one call and it is how most software is signed.
            uint hr = VerifyEmbedded(path);

            // Only a complete absence of an embedded signature justifies looking in the catalogs.
            // A file whose own signature is present but broken has already given its answer, and
            // falling through would let a tampered binary borrow a catalog's trust.
            string signerSource = path;

            if (hr == TrustENoSignature)
            {
                CatalogOutcome outcome = FindCatalog(path, out string? catalog, out string? memberTag);

                // "No catalog covers this file" and "this file could not be hashed" look the same
                // from the outside and mean opposite things. Only the first one licenses the claim
                // that the file is unsigned; the second is a file we could not read, and saying
                // "unsigned" about it would be an accusation built on a failed open.
                if (outcome == CatalogOutcome.Unreadable) return Unreadable;
                if (outcome == CatalogOutcome.NotCovered) return UnsignedInfo;
                if (catalog is null || memberTag is null) return UnsignedInfo;

                hr = VerifyCatalog(path, catalog, memberTag);
                signerSource = catalog;
            }

            SignatureStatus status = MapStatus(hr);

            if (status is SignatureStatus.Unsigned or SignatureStatus.Unreadable)
                return status == SignatureStatus.Unsigned ? UnsignedInfo : Unreadable;

            // The signer is read from whichever file actually carries the signature: the binary
            // itself when embedded, the .cat when catalog-signed. A catalog vouches for thousands
            // of files, so that read is cached against the catalog path — without it, every system
            // binary in a scan would re-parse the same multi-megabyte .cat.
            SignerIdentity identity = signerSource == path
                ? ReadSignerIdentity(signerSource)
                : CatalogSigners.GetOrAdd(signerSource, ReadSignerIdentity);

            // The trust gate is part of the definition, not an extra precaution. Anyone can mint a
            // self-signed certificate that says "Microsoft Corporation"; only a chain Windows
            // actually trusts makes that claim mean anything. Expired is allowed through because a
            // genuine Microsoft binary whose certificate has since lapsed still chained to a
            // trusted root, and treating it as third-party would flag Windows' own files.
            bool isMicrosoft =
                status is SignatureStatus.Valid or SignatureStatus.Expired &&
                identity.IsMicrosoftOrganisation;

            return new SignatureInfo(status, identity.Name, isMicrosoft);
        }
        catch
        {
            // Anything at all — an unreadable attribute, a file that vanished between the two
            // calls, a native call misbehaving. A scanner that throws on one odd file is worse
            // than one that admits it does not know.
            return Unreadable;
        }
    }

    // -------------------------------------------------------------------------------------------
    // Status mapping
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Turns a <c>WinVerifyTrust</c> HRESULT into a status.
    /// </summary>
    /// <remarks>
    /// The distinctions matter: the rules treat an expired signature very differently from an
    /// untrusted one, and both differently from no signature at all. Anything unrecognised becomes
    /// <see cref="SignatureStatus.Unreadable"/> rather than being folded into a failure bucket,
    /// because guessing in the accusing direction is exactly the false positive this feature
    /// cannot afford.
    /// </remarks>
    private static SignatureStatus MapStatus(uint hr) => hr switch
    {
        Success => SignatureStatus.Valid,

        // No signature is a statement of fact, not a fault, and it is what an ordinary text file
        // reports too.
        TrustENoSignature => SignatureStatus.Unsigned,

        // "I have no idea how to inspect this" is not the same statement as "this carries no
        // signature", and only the second one is safe for a rule to act on. Both stay Unreadable.
        TrustESubjectFormUnknown => SignatureStatus.Unreadable,
        TrustEProviderUnknown => SignatureStatus.Unreadable,

        CertEExpired => SignatureStatus.Expired,

        TrustEExplicitDistrust => SignatureStatus.Untrusted,
        CertEUntrustedRoot => SignatureStatus.Untrusted,
        TrustESubjectNotTrusted => SignatureStatus.Untrusted,
        CertEChaining => SignatureStatus.Untrusted,
        CertEUntrustedTestRoot => SignatureStatus.Untrusted,

        // The file was modified after it was signed. Not "unsigned" — the signature is present and
        // no longer matches, which is a stronger statement.
        TrustEBadDigest => SignatureStatus.Untrusted,

        CryptERevoked => SignatureStatus.Revoked,
        CertERevoked => SignatureStatus.Revoked,

        // Revocation was requested but could not be established from the local cache, which is the
        // normal case on a machine that has never fetched the CRL. The signature itself verified,
        // so reporting anything worse than Valid here would flag ordinary software.
        CertERevocationFailure => SignatureStatus.Valid,
        CryptERevocationOffline => SignatureStatus.Valid,
        CryptENoRevocationCheck => SignatureStatus.Valid,

        _ => SignatureStatus.Unreadable,
    };

    // -------------------------------------------------------------------------------------------
    // WinVerifyTrust
    // -------------------------------------------------------------------------------------------

    private static uint VerifyEmbedded(string path)
    {
        WINTRUST_FILE_INFO fileInfo = new()
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        IntPtr block = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());

        try
        {
            Marshal.StructureToPtr(fileInfo, block, fDeleteOld: false);
            return RunVerify(WtdChoiceFile, block);
        }
        finally
        {
            // StructureToPtr allocated native copies of the string fields; DestroyStructure is
            // what releases them. FreeHGlobal alone would leak one string per file verified.
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(block);
            Marshal.FreeHGlobal(block);
        }
    }

    private static uint VerifyCatalog(string memberPath, string catalogPath, string memberTag)
    {
        WINTRUST_CATALOG_INFO catalogInfo = new()
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
            dwCatalogVersion = 0,
            pcwszCatalogFilePath = catalogPath,
            pcwszMemberTag = memberTag,
            pcwszMemberFilePath = memberPath,
            hMemberFile = IntPtr.Zero,
            pbCalculatedFileHash = IntPtr.Zero,
            cbCalculatedFileHash = 0,
            pcCatalogContext = IntPtr.Zero,
            hCatAdmin = IntPtr.Zero,
        };

        IntPtr block = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());

        try
        {
            Marshal.StructureToPtr(catalogInfo, block, fDeleteOld: false);
            return RunVerify(WtdChoiceCatalog, block);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(block);
            Marshal.FreeHGlobal(block);
        }
    }

    /// <summary>
    /// Issues the verify call and then always issues the matching close call.
    /// </summary>
    /// <remarks>
    /// <c>WTD_STATEACTION_VERIFY</c> allocates state that <c>WTD_STATEACTION_CLOSE</c> releases.
    /// Skipping the close leaks that state for every file, and a scan touches hundreds — this is a
    /// real handle leak, not a theoretical one, which is why the close sits in a finally rather
    /// than after the return value is inspected.
    /// </remarks>
    private static uint RunVerify(uint unionChoice, IntPtr unionBlock)
    {
        Guid action = WintrustActionGenericVerifyV2;

        WINTRUST_DATA data = new()
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            pPolicyCallbackData = IntPtr.Zero,
            pSIPClientData = IntPtr.Zero,

            // No dialog may ever appear. This runs on a background thread during a scan, and a
            // modal trust prompt there would be an unclosable window with no owner.
            dwUIChoice = WtdUiNone,

            // Revocation is checked across the chain, but see dwProvFlags: retrieval is
            // cache-only, so this never reaches the network.
            fdwRevocationChecks = WtdRevokeWholeChain,

            dwUnionChoice = unionChoice,
            pUnion = unionBlock,
            dwStateAction = WtdStateActionVerify,
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = IntPtr.Zero,
            dwProvFlags = WtdCacheOnlyUrlRetrieval | WtdSaferFlag,
            dwUIContext = 0,
            pSignatureSettings = IntPtr.Zero,
        };

        try
        {
            // hwnd = INVALID_HANDLE_VALUE tells wintrust there is no parent window and no UI.
            return unchecked((uint)WinVerifyTrust(InvalidHandleValue, ref action, ref data));
        }
        finally
        {
            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(InvalidHandleValue, ref action, ref data);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Catalog lookup
    // -------------------------------------------------------------------------------------------

    /// <summary>Result of looking for a catalog that covers a file.</summary>
    private enum CatalogOutcome
    {
        /// <summary>A catalog vouches for this file.</summary>
        Found,

        /// <summary>The file was hashed successfully and no catalog contains that hash.</summary>
        NotCovered,

        /// <summary>The file could not be hashed, so nothing can be concluded either way.</summary>
        Unreadable,
    }

    /// <summary>
    /// Finds the Windows catalog that vouches for <paramref name="path"/>, by hashing the file and
    /// asking the catalog database which <c>.cat</c> contains that hash.
    /// </summary>
    /// <param name="catalog">The catalog path when one was found.</param>
    /// <param name="memberTag">
    /// The hash rendered as uppercase hex. <c>WinVerifyTrust</c> needs it to locate the member
    /// entry inside the catalog.
    /// </param>
    /// <remarks>
    /// SHA-256 is tried first and SHA-1 second. Current Windows catalogs are SHA-256; the SHA-1
    /// pass is what still resolves older third-party driver catalogs, and skipping it would report
    /// those files as unsigned. A file that cannot be opened fails on the first algorithm and is
    /// reported as such rather than being retried pointlessly.
    /// </remarks>
    private static CatalogOutcome FindCatalog(string path, out string? catalog, out string? memberTag)
    {
        foreach (string algorithm in CatalogHashAlgorithms)
        {
            CatalogOutcome outcome = FindCatalog(path, algorithm, out catalog, out memberTag);
            if (outcome != CatalogOutcome.NotCovered) return outcome;
        }

        catalog = null;
        memberTag = null;
        return CatalogOutcome.NotCovered;
    }

    private static CatalogOutcome FindCatalog(
        string path, string algorithm, out string? catalog, out string? memberTag)
    {
        catalog = null;
        memberTag = null;

        IntPtr admin = IntPtr.Zero;
        IntPtr catalogContext = IntPtr.Zero;
        IntPtr hash = IntPtr.Zero;

        try
        {
            if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
                return CatalogOutcome.Unreadable;

            // FileShare.ReadWrite | Delete: a running program's own image is open for execution,
            // and a stricter share mode would fail on exactly the files most worth checking.
            using FileStream stream = new(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            IntPtr handle = stream.SafeFileHandle.DangerousGetHandle();

            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, IntPtr.Zero, 0);
            if (size == 0) return CatalogOutcome.Unreadable;

            hash = Marshal.AllocHGlobal((int)size);

            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0))
                return CatalogOutcome.Unreadable;

            // From here the file has been hashed successfully, so a miss is a real miss: this file
            // is genuinely in no catalog.
            catalogContext = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catalogContext == IntPtr.Zero) return CatalogOutcome.NotCovered;

            CATALOG_INFO info = new() { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catalogContext, ref info, 0))
                return CatalogOutcome.NotCovered;

            if (string.IsNullOrWhiteSpace(info.wszCatalogFile)) return CatalogOutcome.NotCovered;

            catalog = StripExtendedPrefix(info.wszCatalogFile);
            memberTag = ToHex(hash, size);
            return CatalogOutcome.Found;
        }
        catch
        {
            // Most often the file could not be opened at all: held exclusively by another process,
            // or denied by ACLs. Either way nothing can be concluded about its signature.
            return CatalogOutcome.Unreadable;
        }
        finally
        {
            if (hash != IntPtr.Zero) Marshal.FreeHGlobal(hash);

            // Both contexts are released in reverse order of acquisition, on every path. The
            // catalog context must go before the admin context that produced it.
            if (catalogContext != IntPtr.Zero && admin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(admin, catalogContext, 0);

            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static readonly string[] CatalogHashAlgorithms = ["SHA256", "SHA1"];

    private static string ToHex(IntPtr buffer, uint length)
    {
        byte[] bytes = new byte[length];
        Marshal.Copy(buffer, bytes, 0, (int)length);
        return Convert.ToHexString(bytes);
    }

    /// <summary>
    /// Drops a <c>\\?\</c> prefix. The catalog database hands paths back in extended form, and
    /// that prefix would make the path look like a UNC share to anything that inspects it.
    /// </summary>
    private static string StripExtendedPrefix(string path) =>
        path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;

    // -------------------------------------------------------------------------------------------
    // Signer identity
    // -------------------------------------------------------------------------------------------

    /// <summary>Publisher facts read off a signing certificate. Independent of the trust outcome.</summary>
    /// <param name="Name">Display name for the publisher, or <see langword="null"/> if unreadable.</param>
    /// <param name="IsMicrosoftOrganisation">
    /// Whether the certificate's organisation is Microsoft Corporation. This is only what the
    /// certificate <em>claims</em>; the caller still has to gate it on the signature verifying.
    /// </param>
    private sealed record SignerIdentity(string? Name, bool IsMicrosoftOrganisation)
    {
        public static SignerIdentity Unknown { get; } = new(null, false);
    }

    /// <summary>
    /// Publisher of each catalog encountered, keyed by catalog path. One <c>.cat</c> covers
    /// thousands of Windows files, so this turns a per-file parse into a per-catalog one.
    /// </summary>
    private static readonly ConcurrentDictionary<string, SignerIdentity> CatalogSigners =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Reads the signing certificate out of a file that carries a signature — either a signed
    /// binary or a <c>.cat</c> — and describes the publisher.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This deliberately does not use <c>X509Certificate.CreateFromSignedFile</c>. That API is
    /// obsolete on this framework (SYSLIB0057) and would break the project's zero-warning rule,
    /// and independently of that it throws on any file without an <em>embedded</em> signature —
    /// which is every catalog-signed Windows binary, the exact case this class has to get right.
    /// <c>CryptQueryObject</c> is the underlying Win32 call it wrapped, and it reads both forms.
    /// </para>
    /// <para>
    /// The content-type filter is doing real work and must not be widened to
    /// <c>CERT_QUERY_CONTENT_FLAG_ALL</c>. A <c>.cat</c> is a PKCS#7 SignedData whose payload is a
    /// <b>Certificate Trust List</b>, and if the CTL type is among the accepted ones then
    /// <c>CryptQueryObject</c> reports it as a CTL and hands back a <see langword="null"/> message
    /// handle — leaving no signer for any catalog-signed file, which is most of Windows. Asking
    /// only for the PKCS#7 types makes it parse the outer SignedData instead, and one code path
    /// then covers both signing forms.
    /// </para>
    /// <para>
    /// Failure here is not failure overall: the trust decision is already made by this point, so
    /// an unreadable signer costs the publisher name and nothing else.
    /// </para>
    /// </remarks>
    private static SignerIdentity ReadSignerIdentity(string path)
    {
        IntPtr store = IntPtr.Zero;
        IntPtr message = IntPtr.Zero;
        IntPtr certInfo = IntPtr.Zero;
        IntPtr context = IntPtr.Zero;

        try
        {
            if (!CryptQueryObject(
                    CertQueryObjectFile, path,
                    CertQueryContentFlagSignatures, CertQueryFormatFlagAll, 0,
                    out _, out _, out _, out store, out message, out _))
                return SignerIdentity.Unknown;

            if (store == IntPtr.Zero || message == IntPtr.Zero) return SignerIdentity.Unknown;

            // Two-call idiom: ask for the size, then for the data.
            uint size = 0;
            if (!CryptMsgGetParam(message, CmsgSignerCertInfoParam, 0, IntPtr.Zero, ref size))
                return SignerIdentity.Unknown;

            if (size == 0) return SignerIdentity.Unknown;

            certInfo = Marshal.AllocHGlobal((int)size);
            if (!CryptMsgGetParam(message, CmsgSignerCertInfoParam, 0, certInfo, ref size))
                return SignerIdentity.Unknown;

            // The signer's issuer and serial number, used to pick that exact certificate out of
            // the set the signature carries.
            context = CertFindCertificateInStore(
                store, X509AsnEncoding | Pkcs7AsnEncoding, 0,
                CertFindSubjectCert, certInfo, IntPtr.Zero);

            if (context == IntPtr.Zero) return SignerIdentity.Unknown;

            using X509Certificate2 certificate = new(context);

            return new SignerIdentity(DescribeSigner(certificate), IsMicrosoftOrganisation(certificate));
        }
        catch
        {
            return SignerIdentity.Unknown;
        }
        finally
        {
            if (context != IntPtr.Zero) CertFreeCertificateContext(context);
            if (certInfo != IntPtr.Zero) Marshal.FreeHGlobal(certInfo);
            if (message != IntPtr.Zero) CryptMsgClose(message);
            if (store != IntPtr.Zero) CertCloseStore(store, 0);
        }
    }

    /// <summary>
    /// Picks the most recognisable name on the certificate: the organisation if it has one,
    /// otherwise the common name.
    /// </summary>
    /// <remarks>
    /// Organisation first because that is the legal entity a certificate authority verified, and
    /// it is what a user would recognise. Microsoft's own binaries illustrate the difference —
    /// their common name is "Microsoft Windows" but the organisation is "Microsoft Corporation".
    /// </remarks>
    private static string? DescribeSigner(X509Certificate2 certificate)
    {
        string? organisation = FindRdn(certificate, OrganisationOid);
        if (!string.IsNullOrWhiteSpace(organisation)) return organisation.Trim();

        string? common = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        if (!string.IsNullOrWhiteSpace(common)) return common.Trim();

        return string.IsNullOrWhiteSpace(certificate.Subject) ? null : certificate.Subject;
    }

    /// <summary>
    /// True when the certificate's organisation is Microsoft Corporation.
    /// </summary>
    /// <remarks>
    /// Matched against the parsed organisation attribute rather than by searching the subject
    /// string. A substring test over the whole subject would accept
    /// <c>CN=Not Microsoft Corporation</c>, and the point of this flag is to be trustworthy enough
    /// that rules can suppress findings on it.
    /// </remarks>
    private static bool IsMicrosoftOrganisation(X509Certificate2 certificate)
    {
        string? organisation = FindRdn(certificate, OrganisationOid);

        return organisation is not null &&
               string.Equals(organisation.Trim(), MicrosoftOrganisation, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads one attribute out of the subject's distinguished name.</summary>
    private static string? FindRdn(X509Certificate2 certificate, string oid)
    {
        try
        {
            foreach (X500RelativeDistinguishedName rdn in
                     certificate.SubjectName.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.GetSingleElementType().Value == oid) return rdn.GetSingleElementValue();
            }
        }
        catch
        {
            // A malformed or multi-valued RDN. No name is better than a wrong one.
        }

        return null;
    }

    /// <summary>X.500 <c>organizationName</c>.</summary>
    private const string OrganisationOid = "2.5.4.10";

    private const string MicrosoftOrganisation = "Microsoft Corporation";

    // -------------------------------------------------------------------------------------------
    // Interop. DllImport rather than LibraryImport: the source-generated variant needs
    // AllowUnsafeBlocks, which this project does not enable.
    // -------------------------------------------------------------------------------------------

    private static readonly IntPtr InvalidHandleValue = new(-1);

    /// <summary><c>WINTRUST_ACTION_GENERIC_VERIFY_V2</c> — the standard Authenticode policy.</summary>
    private static readonly Guid WintrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint Success = 0;

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;

    /// <summary>Consult only cached CRLs, never the network. This is what keeps a scan responsive.</summary>
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const uint WtdSaferFlag = 0x00000100;

    private const uint TrustEProviderUnknown = 0x800B0001;
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustESubjectNotTrusted = 0x800B0004;
    private const uint TrustENoSignature = 0x800B0100;
    private const uint CertEExpired = 0x800B0101;
    private const uint CertEUntrustedRoot = 0x800B0109;
    private const uint CertEChaining = 0x800B010A;
    private const uint CertERevoked = 0x800B010C;
    private const uint CertEUntrustedTestRoot = 0x800B010D;
    private const uint CertERevocationFailure = 0x800B010E;
    private const uint TrustEExplicitDistrust = 0x800B0111;
    private const uint TrustEBadDigest = 0x80096010;
    private const uint CryptENoRevocationCheck = 0x80092012;
    private const uint CryptERevocationOffline = 0x80092013;
    private const uint CryptERevoked = 0x80092010;

    private const uint CertQueryObjectFile = 1;

    /// <summary>
    /// <c>CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | ..._PKCS7_SIGNED_EMBED</c> — the two forms a
    /// signature arrives in. Deliberately narrow; see <see cref="ReadSignerIdentity"/>.
    /// </summary>
    private const uint CertQueryContentFlagSignatures = 0x00000100 | 0x00000400;
    private const uint CertQueryFormatFlagAll = 0x0000000E;
    private const uint CmsgSignerCertInfoParam = 7;
    private const uint CertFindSubjectCert = 0x000B0000;
    private const uint X509AsnEncoding = 0x00000001;
    private const uint Pkcs7AsnEncoding = 0x00010000;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    /// <summary>
    /// <c>WINTRUST_DATA</c>. <c>pUnion</c> stands for the anonymous union of subject pointers;
    /// which member it is read as is decided by <c>dwUnionChoice</c>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, IntPtr pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatalogContext);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptQueryObject(
        uint dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)] string pvObject,
        uint dwExpectedContentTypeFlags,
        uint dwExpectedFormatTypeFlags,
        uint dwFlags,
        out uint pdwMsgAndCertEncodingType,
        out uint pdwContentType,
        out uint pdwFormatType,
        out IntPtr phCertStore,
        out IntPtr phMsg,
        out IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg, uint dwParamType, uint dwIndex, IntPtr pvData, ref uint pcbData);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertFindCertificateInStore(
        IntPtr hCertStore, uint dwCertEncodingType, uint dwFindFlags,
        uint dwFindType, IntPtr pvFindPara, IntPtr pPrevCertContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);
}
