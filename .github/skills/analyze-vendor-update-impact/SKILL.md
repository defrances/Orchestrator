---
name: analyze-vendor-update-impact
description: Analyze FindUpdates station report JSON against the full DesktopApplication main branch, score install vs skip risk, cluster same-coupling CVEs into one analysis file per workstation, then write JSON under issues-out/. Do not open GitHub Issues. Use when given findupdates-report-json or report.json.
---

# Analyze vendor update impact

You are an advisory analyst. You do not authorize install, approval, or deploy.
HOLD and BLOCK stay HOLD and BLOCK. Do not call `gh issue create`.
Write JSON files only under `issues-out/`. Results are emailed; do not publish GitHub Issues.

The application under analysis is **always** https://github.com/defrances/DesktopApplication **branch `main`**.
Do not analyze another branch, a single project file, or "the idea of a WPF app".

## Inputs

| Path | What it is |
| --- | --- |
| `inputs/report.json` | FindUpdates `findupdates-report-json` (`kind=station_report`) |
| `workspace/DesktopApplication/` | Full git checkout of `defrances/DesktopApplication` @ `main` |
| `workspace/desktop-application-inventory.md` | File list + HEAD of that `main` checkout |
| `workspace/sbom/DesktopApplication.sbom.spdx.json` | Optional SPDX SBOM from the triggering CI run |

If `inputs/report.json` is missing, stop.
If `workspace/DesktopApplication` is missing, stop.
If HEAD is not `main`, stop. Do not invent repository contents.

## Analyze the entire main repository first

Complete this pass **before** deciding any issue. Do not skip files because they look unrelated.

1. Read `workspace/desktop-application-inventory.md`. Confirm branch `main` and note HEAD.
2. Walk the whole tree under `workspace/DesktopApplication/`, excluding `.git/`, `bin/`, `obj/`.
3. Read every source and project file, at least:
   - `DesktopApplication.sln`
   - `README.md`
   - `.github/workflows/ci.yml`
   - `.github/workflows/notify-orchestrator.yml`
   - `src/DesktopApplication/DesktopApplication.csproj`
   - `src/DesktopApplication/App.xaml`, `App.xaml.cs`
   - `src/DesktopApplication/MainWindow.xaml`, `MainWindow.xaml.cs`
   - `src/DesktopApplication/MainViewModel.cs`
   - `src/DesktopApplication/RelayCommand.cs`
   - `src/DesktopApplication/AssemblyInfo.cs`
   - `src/DesktopApplication/app.manifest`
   - `src/DesktopApplication.Core/DesktopApplication.Core.csproj`
   - `src/DesktopApplication.Core/NoteStore.cs`
   - `src/DesktopApplication.Core/SystemInformation.cs`
   - `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` (if present)
   - `tests/DesktopApplication.Tests/DesktopApplication.Tests.csproj`
   - `tests/DesktopApplication.Tests/NoteStoreTests.cs`
   - `tests/DesktopApplication.Tests/SystemInformationProviderTests.cs`
   - `tests/DesktopApplication.Tests/InsecureVendorBulletinClientTests.cs` (if present)
4. From those files, extract facts (cite path + symbol), including:
   - Target framework, `UseWPF`, `OutputType=WinExe`, project references
   - Self-contained `win-x64` publish and SBOM generation in CI (not assumed from memory)
   - `app.manifest`: Windows 10 compatibility GUID, `dpiAware`, `PerMonitorV2`
   - UI/view-model behavior in `MainWindow` / `MainViewModel`
   - `%AppData%\DesktopApplication\notes.txt` via `NoteStore`
   - OS/user/machine/runtime strings via `SystemInformationProvider` (`RuntimeInformation`)
   - HTTPS / TLS via `InsecureVendorBulletinClient` / `CheckBulletinCommand` when those files exist
   - Tests that lock file I/O, OS information, or TLS-bypass contracts
5. History on **main only**: `git -C workspace/DesktopApplication log --oneline -20` and diffs that change runtime, packaging, I/O, WPF, TLS, or OS assumptions.
6. SBOM if present: map packages to files you actually read. A SBOM row is not enough without a code path.

Write a short working map (in your reasoning, not as an extra GitHub issue): what the app does, how it is built, which OS/runtime APIs it calls, which local files it touches.

## Report schema

`report.json` fields:

- `source`, `correlation_id`, `disclaimer`, `candidate_count`
- `items[]` listed station rows:
  - `device_id`, `model`, `device_role`, `deployment_group`
  - `os_product`, `os_build`, `clinical_criticality`, `network_exposure`
  - `advisory_id`, `title`, `vendor`, `package`, `cve_ids`
  - `action` (`candidate_for_validation` / `do_not_install` / `not_in_scope`)
  - `verdict`, `policy_result`, `risk_score`, `severity`
  - `explanation`, `official_url`, `listed`

After the full-repo pass, score remaining rows, then **cluster** (do not file one issue per CVE).

## Coupling to this codebase

DesktopApplication on `main` is a small self-contained WPF client. OS vendor rows are in scope only when you can name a **file on main** that would feel the change.

Typical couplings from this repo (use only if the file supports it):

| `cluster_key` | Host component | Files on `main` |
| --- | --- | --- |
| `schannel-tls` | Schannel / TLS / HTTP | `InsecureVendorBulletinClient.cs`, `MainViewModel.CheckBulletinCommand` |
| `win32k-wpf` | Win32k / windowing / DPI | `MainWindow.xaml`, `app.manifest`, `UseWPF` |
| `dwm-wpf` | DWM composition | `MainWindow.xaml`, `app.manifest` `PerMonitorV2` |
| `shell-launch` | Shell / exe identity | `OutputType=WinExe`, `app.manifest` assembly identity |
| `ntfs-notes` | NTFS / profile files | `NoteStore.cs`, notes tests |
| `os-dotnet` | Host .NET / .NET Framework KB | `ci.yml` `--self-contained true`, SBOM runtime packs, `SystemInformation.cs` |

Do **not** invent a new `cluster_key` when one of these fits. Do **not** claim an OS .NET / .NET Framework KB patches the runtime inside the published exe unless you show the publish is framework-dependent. On current `main`, CI publishes `--self-contained true` for `win-x64`.

## Score the risk of this update

After the full-repo pass, score **both directions** for every remaining row. The question is not only "does this CVE sound serious". It is whether **this codebase on `main`** needs the update, survives the update, or breaks because of it.

Look for a real library or logic path:

- `PackageReference` / `ProjectReference` in `*.csproj`
- packages in the SBOM that the published exe actually embeds
- BCL / WPF / Win32 / TLS APIs the `.cs` / `.xaml` files call
- tests that freeze those contracts

Then assign:

| Field | Allowed values | Meaning |
| --- | --- | --- |
| `required_for_app` | `required` / `not_required` / `unknown` | `required` only if the app on `main` will fail, refuse to start, or stay on a library version the code cannot run without this vendor package |
| `install_risk` | `breaks_app` / `may_break_app` / `compatible` / `unknown` | Risk **if the vendor update is installed** on the station |
| `skip_risk` | `app_will_fail` / `stays_vulnerable` / `no_app_impact` / `unknown` | Risk **if the update is not installed** |
| `compatibility` | `incompatible` / `compatible` / `unknown` | Does current `main` logic work with the proposed vendor bits? |

Rules:

1. **`required_for_app: required` and `skip_risk: app_will_fail`** only with a cited file that loads the patched component. "Windows has a CVE" is not enough. Current `main` has no third-party `PackageReference`; Core is `net9.0` BCL only.
2. **Self-contained publish:** an OS .NET KB almost never makes the app "not work without the KB". Say `not_required` and `skip_risk: no_app_impact` for `os-dotnet` unless you prove framework-dependent load.
3. **`install_risk: breaks_app` / `may_break_app`** when host OS/WPF/Shell/DPI/reboot would change behavior of files you read. That is incompatibility **with** the vendor update, not a reason to install it.
4. If FindUpdates is `do_not_install` / HOLD / BLOCK, keep that verdict. A high `skip_risk` does **not** override HOLD/BLOCK.
5. If you cannot match the vendor package to a library or logic path on `main`, set `required_for_app: not_required`, `skip_risk: no_app_impact`, and **do not file** unless HOLD/BLOCK must be recorded.

## Cluster before writing issues

Reviewers need **one card per coupling on a workstation**, not one card per CVE.

A live run that produced 20 issues with six repeated rationales (Schannel ×4, Win32k ×3, DWM ×2, Shell ×3, NTFS ×4, .NET ×4) is a failure of this skill.

After scoring, group rows that share **all** of:

- the same `device_id`
- the same `cluster_key` (same cited files, same failure mode)
- the same four risk fields
- the same reviewer action (validate / HOLD / BLOCK)

Write **one** issue for that group. Put every member advisory, package, CVE, policy, and score in the Updates table. For each row, if `official_url` is a `https://` value from that same report row, make **only Package** a markdown link (`[KB5122871](https://msrc.microsoft.com/...)`). Do not link Title, Advisory, or CVEs. Never invent or rewrite the URL. The "How this can affect" section is written **once** for the coupling. Do not copy the same paragraph and only swap the CVE title.

Do **not** file a second issue because:

- two rows share a KB but are different CVEs of the same component
- titles differ only by DoS / EoP / RCE / bypass on the same host stack
- `risk_score` differs while the cited files and recommended action stay the same

Split into two issues on the same station only when the **cited files** or **install vs skip recommendation** actually differ (for example BLOCK vs candidate_for_validation, or `os-dotnet` HOLD vs `schannel-tls` validate).

Prefer `candidate_for_validation` and high `risk_score` when choosing which member rows to keep in a cluster. File a HOLD/BLOCK cluster only when installing would be harmful **or** the app is explicitly not affected (`os-dotnet`) and reviewers must not treat the KB as an app patch. The issue must say do not install when policy is HOLD/BLOCK.

Cap: at most **8** individual issue files (one cluster × station each). Overflow goes to `issues-out/summary.json`.

Skip:

- `not_in_scope` unless `main` still targets that OS/package
- Media/codec/network CVEs with no caller on `main`
- Duplicate `cluster_key` + `device_id` pairs
- Issues whose only evidence is "it is a Windows WPF app"
- Extra issues that would repeat an already-written coupling paragraph

## Output files

`issues-out/01-<cluster_key>-<device_id>.json`

Required keys: `title`, `body`, `advisory_id`, `device_id`, `cluster_key`, `labels`, `required_for_app`, `install_risk`, `skip_risk`, `compatibility`.

Set `advisory_id` to the same value as `cluster_key` (stable fingerprint). Do not use a single CVE id as `advisory_id` when the body lists a cluster.

Title format:

`[Impact] {cluster_key} on {device_id} — {short risk}`

`{short risk}` describes the coupling, not one CVE (for example `Schannel TLS path has no defense in depth`, `Win32k may change WPF DPI`, `OS .NET KB does not patch bundled runtime`).

Labels must include `vendor-update-impact` and `workstation:{device_id}`.

The body must follow [issue-template.md](issue-template.md), include

`<!-- impact:{cluster_key}:{device_id} -->`

and cite **at least one path under `workspace/DesktopApplication/`** from `main` (file plus what you read there). "WPF / net9 / SBOM present" is not sufficient evidence.

If nothing qualifies, write `issues-out/none.json`:

```json
{
  "issues": []
}
```

Do not include secrets, tokens, PHI, or patient identifiers. Official URLs only if already present on the report row.
