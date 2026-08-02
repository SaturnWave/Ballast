# Ballast — working notes

A disk maintenance app for Windows: find what is using the space, and get rid of it safely.
C#/.NET 10, WinUI 3, unpackaged and self-contained.

Ballast is the dead weight a ship drops to move faster. That is the product in one line, and it is
also the test for a new feature: does this help someone drop weight, or is it decoration?

---

## 1. The safety doctrine

**This app runs elevated and deletes things. Read this before changing anything under `Cleaning/`,
`Programs/` or `Util/`.**

`app.manifest` requests `requireAdministrator`, so the guards below are the only thing standing
between a bug and an unbootable machine. Do not weaken one to make a feature easier.

### Two deletion paths, deliberately opposite

| | Automated junk cleaning | User-chosen files (Disk Space) |
| --- | --- | --- |
| Guard | `Util/PathSafety.cs` — **allowlist** | `Util/SystemPathGuard.cs` — **denylist** |
| Rule | only paths *inside* known junk roots | anything except OS-critical locations |
| Destination | deleted outright | **Recycle Bin** by default (`FOF_ALLOWUNDO`) |
| Chosen by | the app | the human, item by item, then confirmed |

An allowlist is right when *the app* decides, because one missing denylist entry means data loss.
A denylist is right when *the human* picked that exact file, because then the guard's only job is to
stop them destroying Windows — not to second-guess their own data. Wanting to use one where the
other belongs means you have misread which side of that line you are on.

### Rules that must not be broken

- **Scanning never deletes.** Deletion is always a separate, explicitly confirmed step.
- **Every path is re-validated immediately before deletion.** A scan result is input, not permission.
- **Cloud placeholders are never traversed or deleted** (`Util/CloudFiles.cs`). Their logical size is
  not real local space, and touching one makes the sync client download it. This machine has
  OneDrive *and* two Google Drive mounts, so it comes up constantly.
- **Junctions and symlinks are never followed.** A junction inside `%TEMP%` pointing at `C:\Windows`
  needs no admin to create, and following it was a real hole found in review.
- **Locked files are skipped and reported, never forced.**
- **`BytesFreed` is measured, not assumed** — counted per file as it is actually removed.
- **Every outcome is written to `Util/ActionLog.cs`.** A refusal that logs nothing is exactly how the
  startup-toggle bug stayed invisible for a whole session.
- **The uninstaller never deletes.** It starts the vendor's own uninstaller and stops. Leftovers may
  be *reported*, never removed.
- **Confirmation dialogs default to Cancel** (`DefaultButton = ContentDialogButton.Close`). The
  permanent-delete dialog is deliberately a *different* dialog, not the Recycle Bin one with the
  verb swapped.

### Deletion risk levels

`Util/DeletionRisk.cs` grades every path 1-5, and the treemap colours by it:

| | Level | Meaning |
| --- | --- | --- |
| 1 | System | never delete — anything `SystemPathGuard.IsProtected` refuses |
| 2 | Risky | installed programs, `AppData\Roaming`, synced cloud content |
| 3 | Caution | the user's own documents and media |
| 4 | ProbablySafe | Downloads, `bin`/`obj`/`node_modules`, old installers |
| 5 | Safe | anything `PathSafety.IsDeletable` allows |

A folder is never allowed to look safer than its contents.

---

## 2. Layout

```
Ballast.slnx
├─ Ballast.Core/     class library, NO UI dependency — all risky logic lives here
│  ├─ Cleaning/         junk scanners, CleaningService, UserFileDeleter
│  ├─ DiskAnalysis/     tree scan, drives, squarified treemap maths, ScanCache
│  ├─ Startup/          autostart enumeration + reversible toggling
│  ├─ Programs/         installed-program enumeration + uninstall launching
│  └─ Util/             PathSafety, SystemPathGuard, DeletionRisk, CloudFiles, ActionLog
├─ Ballast.App/      WinUI 3, MVVM (CommunityToolkit.Mvvm)
└─ Ballast.Tests/    xUnit — 405 tests
```

`Core` has no UI dependency on purpose: every dangerous decision is testable without launching a
window. Keep it that way. If a guard needs a `DispatcherQueue`, the design is wrong.

The most valuable tests are the ones asserting the app **refuses** to act — including one that
plants a real file in `Documents` and verifies it survives a cleanup pass.

---

## 3. Commands

```bash
dotnet build Ballast.slnx                              # must be 0 errors AND 0 warnings
dotnet test Ballast.Tests/Ballast.Tests.csproj         # 405 passing
dotnet publish Ballast.App/Ballast.App.csproj -c Release -r win-x64 -o app
graphify update .                                      # refresh the knowledge graph, ~9s, no tokens
```

Building the solution puts output in `bin/x64/Debug/...` (the `.slnx` pins x64); building the csproj
alone puts it in `bin/Debug/...`. That difference has already caused one "my fix did not work" that
was really the wrong binary being launched — check the path before concluding anything.

**The exe cannot be replaced while an instance is running**, and since it is elevated a
non-elevated shell cannot kill it. Close the window first.

---

## 4. Platform

- **Windows 10 build 19041 (May 2020) and later.** `TargetPlatformMinVersion` says so, the manifest
  carries the Win10/11 `supportedOS` GUID, and nothing in the codebase touches a Windows 11-only
  API — no Mica, no `SystemBackdrop`, no corner-preference DWM calls. Keep it that way: if you add
  one, gate it, do not raise the floor.
- Unpackaged (`WindowsPackageType=None`) and self-contained: no MSIX signing, no separately
  installed Windows App Runtime. `EnableMsixTooling` is still required — the SDK uses it to generate
  the embedded `resources.pri` that XAML needs at runtime.
- `NuGet.config` pins restore to nuget.org only, because a machine-wide private feed was unreachable
  and broke restore.

---

## 5. Design system

Quiet and content-first: warm paper in light, graphite in dark, **one** muted indigo accent,
hairline borders, no drop shadows, generous whitespace, hierarchy from type rather than colour.

Never hardcode a colour. Use the tokens in `Styles/`:

- Brushes: `AppBackgroundBrush AppSurfaceBrush AppSurfaceRaisedBrush AppBorderBrush AppHoverBrush
  AppPressedBrush AppTextBrush AppTextSecondaryBrush AppTextTertiaryBrush AppAccentBrush
  AppAccentHoverBrush AppAccentPressedBrush AppAccentSubtleBrush AppOnAccentBrush AppDangerBrush
  AppDangerSubtleBrush AppOnDangerBrush Risk1Brush…Risk5Brush`
- Text: `TextDisplay TextTitleLarge TextTitle TextHeadline TextBody TextSecondary TextCaption`
- Controls: `AppCard AppRow AppSeparator AppPrimaryButton AppSecondaryButton AppGhostButton
  AppDangerButton AppPill AppProgressBar AppSegmentTrack AppCheckBox` and more in `Controls.xaml`

The accent is indigo specifically because the risk scale owns red→orange→yellow→green. A brand
colour inside that ramp would fight the one piece of colour that actually carries meaning.

Body text is capped around a 680px measure. A paragraph running the full width of a 2200px window is
unreadable, and that restraint is most of why the interface reads as calm.

---

## 6. Hard-won gotchas

Each of these cost real debugging time. They are not style preferences.

**Never hand-write a `ControlTemplate` for `ToggleSwitch`.** It renders perfectly and silently stops
raising `Toggled` — every startup switch looked right and did nothing. Having `SwitchAreaGrid` is not
sufficient, and adding the three `ContentPresenter` parts does not fix it either; both were tried
against the running UI. The switch is now stock and keeps its On/Off label, so state is read in words
rather than inferred from a colour.

**`[ObservableProperty]` goes on a private field**, not a partial property. The partial-property form
generates nothing on this toolchain and produces `CS9248` for every property. `MVVMTK0045` is
suppressed in the csproj with that reasoning written out.

**Single-instance must fail open.** The first version used `AppInstance.FindOrRegisterForKey`, which
left a stale registration after a crash — every later launch redirected into nothing and exited, so
the app stopped opening at all. It is now a named mutex plus a window search, and **if no live window
is found for any reason the process starts normally.** A stray second window beats an app that will
not launch.

**`EstimatedSize` in the uninstall registry is a DWORD in kilobytes, and 0 means unknown.** Rendering
it as "0 KB" tells the user a 4 GB program takes no space. Show an em dash.

**Uninstall strings are not trusted input.** `"C:\Program Files\App\unins000.exe" /S` must not split
on the first space into `C:\Program`. Parsing is four tiers: quoted path, filesystem probe, longest
executable-extension match, then bare command name. There is a test named after the bug.

**Icons load after the rows paint.** The Startup page renders in ~55 ms because scheduled-task
enumeration was moved off the fast path; putting 16 icon extractions in front of that would undo it.
Always `DestroyIcon` — the list rebuilds on every scan.

**`schtasks.exe /query /v` costs ~8 seconds** and is the only way to read trigger types without admin
(the task XML under `System32\Tasks` is not readable by a standard user). Hence the two-phase startup
scan.

**A window capture of the app will come back blank** now that it is elevated — UIPI stops a
non-elevated process reading it. "It builds and the tests pass" is not the same as "it looks right",
and that gap has bitten this project more than once.

---

## 7. Conventions

- Comments explain **why**, not what. This codebase is dense with reasoning about safety decisions;
  match that. A comment restating the line below it is noise.
- XML doc comments on public types and members.
- Guards never throw for an unreadable or malformed path — they return "refused". *Cannot tell* must
  always mean *do not touch*.
- Progress goes through `IProgress<ScanProgress>` marshalled to the UI thread; long operations are
  cancellable.
- Prefer reversible operations. Startup entries are **moved** to a backup key, never deleted. When
  renaming anything that forms a key or folder name, migrate the old one: the CleanMyWin→Ballast
  rename orphaned five real disabled startup entries and would have made them unrecoverable.

---

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

Measured on this repo: `graphify affected "<symbol>"` is by far the most useful of these — "what
breaks if I change this guard" is the question that matters most here, and it answers with file:line
including the tests. `graphify query` is a locator, not an explainer: it points at the right files
but will not tell you what they do. Keep `.gitignore` accurate — without it the graph indexed `obj/`
and half the nodes were build artefacts.
