# Ballast

A disk maintenance app for Windows 11 — find what is using the space, and get rid of it safely.
C#/.NET 10 and WinUI 3.

Ballast is the dead weight a ship drops to move faster, which is what this does to a full disk.

> **Trademark.** The name was chosen to sit well clear of MacPaw's *CleanMyMac*. It has **not**
> been cleared: search TURKPATENT and USPTO in the software class before publishing under it.

---

## Safety model

This is a tool that deletes files, so the design starts from what it must **never** do.

> **The app runs elevated.** `app.manifest` requests `requireAdministrator`, so every launch shows a
> UAC prompt and everything the app deletes runs with full privileges. That makes the guards below
> the only thing standing between a bug and an unbootable machine — do not weaken them. The
> trade-offs, and how to revert to `asInvoker`, are documented in `app.manifest` itself.

### Two deletion paths, deliberately opposite

Files get deleted in two places, under **inverted** rules. That is intentional:

| | Automated junk cleaning | User-chosen files (Disk Space page) |
| --- | --- | --- |
| Guard | `Util/PathSafety.cs` — **allowlist** | `Util/SystemPathGuard.cs` — **denylist** |
| Rule | only paths *inside* known junk roots | anything except OS-critical locations |
| Destination | deleted outright | **Recycle Bin** (`FOF_ALLOWUNDO`) by default |
| Decided by | the app | the human, item by item, then confirmed |

An allowlist is right for junk cleaning: the app decides on its own, and one missing denylist entry
would mean data loss. A denylist is right for the Disk Space page: the user explicitly picked *that*
file and confirmed it, so the guard's only job is to stop them destroying Windows — not to
second-guess their own data. And because that data is irreplaceable, those deletions go to the
Recycle Bin so they can be undone.

| Rule | Where it is enforced |
| --- | --- |
| Scanning never deletes. Deletion is a separate, explicitly confirmed step. | `CleanupPage` confirmation dialog |
| A path is deletable only if it sits **inside** a known junk root (allowlist, not denylist). | `Util/PathSafety.cs` |
| The junk roots themselves are never removed — only their contents. | `PathSafety.IsDeletable` |
| Credential/history stores are rejected by filename, wherever they live. | `PathSafety` sensitive-name list |
| Browser cleaning touches an explicit list of *cache* folder names only. | `Cleaning/BrowserCacheScanner.cs` |
| Junctions, symlinks and cloud placeholders are never traversed or deleted. | `Util/CloudFiles.cs` |
| Files modified in the last 24 h are left alone (a running installer may need them). | `DirectoryJunkScanner.MinimumAge` |
| Every path is re-validated immediately before deletion; a scan result is input, not permission. | `Cleaning/CleaningService.cs` |
| Locked files are skipped and reported, never forced. | `CleaningService.DeleteDirectoryContents` |
| Reported "space freed" counts what was actually removed, measured per file. | `CleaningService` |
| Every deletion is written to an audit log. | `Util/ActionLog.cs` |

The most important tests in the repo are the ones asserting the app **refuses** to act —
including one that plants a real file in `Documents` and verifies it survives a cleanup pass.

### Cloud storage

Placeholder files from OneDrive Files On-Demand, Google Drive and similar are excluded from
every scan. Two reasons: their logical size is not real local disk usage (counting it inflates
every total), and touching one makes the sync client download it. `DriveSummary.IsLikelyCloudMount`
also flags lettered drives that are really account mounts — Google Drive presents itself as a
large FAT32 *fixed* disk, so drive type alone cannot tell them apart.

---

## Layout

```
Ballast.slnx
├─ Ballast.Core/          class library, no UI dependency
│  ├─ Abstractions/          IScanner
│  ├─ Models/                CleanupItem, ScanResult, ScanProgress, CleanReport, JunkCategory
│  ├─ Cleaning/              the junk scanners + CleaningService
│  ├─ DiskAnalysis/          directory tree scan, drive info, squarified treemap
│  ├─ Startup/               autostart enumeration and reversible toggling
│  └─ Util/                  PathSafety, CloudFiles, ByteFormatter, Elevation, ActionLog
├─ Ballast.App/           WinUI 3 desktop app (MVVM)
│  ├─ Styles/                the design system (quiet: paper/graphite, one indigo accent)
│  ├─ Controls/, Converters/
│  ├─ ViewModels/            CommunityToolkit.Mvvm
│  └─ Views/                 Dashboard, Cleanup, Disk Space, Startup, Settings
└─ Ballast.Tests/         xUnit
```

`Core` has no UI dependency, so all the risky logic is unit testable without launching a window.

---

## Features

**Junk cleanup** — user temp, Windows temp, browser caches (Edge/Chrome/Brave/Firefox),
thumbnail & icon cache, crash dumps, Windows Update cache, Recycle Bin. Per-category sizes,
expandable file lists, confirmed delete.

**Disk space** — recursive drive scan (iterative, so deep trees cannot overflow the stack),
largest files and folders, and a squarified treemap with drill-down.

**Startup manager** — registry `Run` keys (HKCU, HKLM, WOW6432Node), user and common startup
folders, and logon-triggered scheduled tasks. Disabling is **reversible**: registry values move
to a `Run-disabled-Ballast` backup key and shortcuts move to a `Disabled-Ballast`
subfolder, rather than being destroyed.

Startup scanning is two-phase because `schtasks.exe /query /v` takes ~8 s (it is the only way to
read trigger types without admin — the task XML under `System32\Tasks` is not readable by a
standard user). `ScanFastAsync` returns registry and folder entries in ~55 ms so the UI paints
immediately; scheduled tasks fold in when they arrive.

---

## Build and run

Requires the .NET 10 SDK. The WinUI project templates are *not* required — the app builds from
the CLI via the `Microsoft.WindowsAppSDK` NuGet package.

```bash
dotnet build Ballast.slnx
```

```bash
dotnet test Ballast.Tests/Ballast.Tests.csproj
```

```bash
dotnet run --project Ballast.App
```

The app is **unpackaged and self-contained** (`WindowsPackageType=None`,
`WindowsAppSDKSelfContained=true`), so it needs no MSIX signing and no separately installed
Windows App Runtime.

`NuGet.config` pins restore to nuget.org only, so an unreachable private feed configured
machine-wide cannot break the build.

### Elevation

The app requests `requireAdministrator`, so every launch shows a UAC prompt. That is deliberate —
it is what makes `C:\Windows\Temp`, the Windows Update cache, HKLM `Run` entries and scheduled
tasks reachable without a second launch. The cost is stated in `app.manifest`, along with how to
go back to `asInvoker`.

Audit log: `%LOCALAPPDATA%\Ballast\logs\`

### Single instance

A second launch surfaces the window already open instead of starting another copy — two cleaners
scanning and deleting the same paths at once would disagree with each other. It is implemented
with a named mutex plus a window search that **fails open**: if no live window can be found for
any reason, the process starts normally. An earlier `AppInstance`-based version left a stale
registration after a crash and stopped the app launching at all, which is far worse than a
duplicate window.

---

## Not in this version

App uninstaller with leftover removal, malware scanning, privacy/history cleaning,
duplicate finder, memory optimiser, MSIX packaging, auto-update.
