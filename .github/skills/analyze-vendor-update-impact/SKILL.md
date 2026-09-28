---
name: analyze-vendor-update-impact
description: Analyze FindUpdates station report JSON against DesktopApplication main, score install vs skip risk, cluster same-coupling CVEs into one analysis file per product configuration, then write JSON under issues-out/. Do not open GitHub Issues. Use when given findupdates-report-json or report.json.
---

# Analyze vendor update impact

You write design-control evidence for product configuration **UVCS configuration 1**.
FindUpdates and this workflow collect facts; they are not the product tool-validation procedure and they do not authorize install.
Do not call `gh issue create`. Write JSON files only under `issues-out/`. Results are emailed.

The application under analysis is **always** https://github.com/defrances/DesktopApplication **branch `main`**.
Do not analyze another branch, a single project file, or "the idea of a WPF app".
The customer-facing product name is **UVCS configuration 1**. Keep repository folder names (`DesktopApplication`) as they are on disk.

## Inputs

| Path | What it is |
| --- | --- |
| `inputs/report.json` | FindUpdates `findupdates-report-json` (`kind=station_report`) |
| `workspace/DesktopApplication/` | Full git checkout of `defrances/DesktopApplication` @ `main` |
| `workspace/desktop-application-inventory.md` | File list + HEAD of that `main` checkout |
| `workspace/sbom/DesktopApplication.sbom.spdx.json` | Optional SPDX SBOM from the triggering CI run |
| `workspace/DesktopApplication/docs/test-plan.md` | Documented Unit / Smoke / Regression ids |
| `workspace/DesktopApplication/docs/security-risk-management.md` | Product patch management under design control |

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
   - `docs/test-plan.md`, `docs/mds2.md`, `docs/security-risk-management.md`
4. From those files, extract facts (cite path + symbol), including:
   - Target framework, `UseWPF`, `OutputType=WinExe`, project references
   - Self-contained `win-x64` publish and SBOM generation in CI (not assumed from memory)
   - `app.manifest`: Windows 10 compatibility GUID, `dpiAware`, `PerMonitorV2`
   - UI/view-model behavior in `MainWindow` / `MainViewModel`
   - `%AppData%\DesktopApplication\notes.txt` via `NoteStore`
   - OS/user/machine/runtime strings via `SystemInformationProvider` (`RuntimeInformation`)
   - HTTPS / TLS via `InsecureVendorBulletinClient` / `CheckBulletinCommand` when those files exist
   - Tests that lock file I/O, OS information, or TLS-bypass contracts
5. History on **main only**: `git -C workspace/DesktopApplication log --oneline -20` and diffs that change runtime, packaging, I/O, WPF, TLS, or OS assumptions. Use this only as analysis input; do **not** put a Recent code section in the email body.
6. SBOM if present: map packages to files you actually read. A SBOM row is not enough without a code path.

Write a short working map (in your reasoning, not as an extra file): what the app does, how it is built, which OS/runtime APIs it calls, which local files it touches.

## Report schema

`report.json` fields (internal FindUpdates names — do not rename them in JSON):

- `source`, `correlation_id`, `disclaimer`, `candidate_count`
- `items[]` listed station rows:
  - `device_id`, `model`, `device_role`, `deployment_group`
  - `os_product`, `os_build`, `clinical_criticality`, `network_exposure`
  - `advisory_id`, `title`, `vendor`, `package`, `cve_ids`
  - `action` (`candidate_for_validation` / `do_not_install` / `not_in_scope`)
  - `verdict`, `policy_result`, `risk_score`, `severity`
  - `explanation`, `official_url`, `listed`

After the full-repo pass, score remaining rows, then **cluster** (do not file one analysis per CVE or per lab station).

## Coupling to this codebase

DesktopApplication on `main` is a small self-contained WPF client shipped as **UVCS configuration 1**. OS vendor rows are in scope only when you can name a **file on main** that would feel the change.

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

Then assign (JSON fields stay these names). In the email **Potential Risks** block, never print only the enum. Use the human label from [issue-template.md](issue-template.md) plus a why sentence with a cited file, SBOM row, or publish fact.

| Field | Allowed values | Meaning | Why the manager must see |
| --- | --- | --- | --- |
| `required_for_app` | `required` / `not_required` / `unknown` | `required` only if the app on `main` will fail, refuse to start, or stay on a library version the code cannot run without this vendor package | `not_required`: exe still starts without this KB, and the patched library is not a product `PackageReference` / not loaded. `required`: name the loader file. |
| `install_risk` | `breaks_app` / `may_break_app` / `compatible` / `unknown` | Risk **if the vendor update is installed** on the host | `compatible`: KB does not replace bits inside the self-contained exe. `may_break_app`: name WPF/DPI/Shell/reboot path. |
| `skip_risk` | `app_will_fail` / `stays_vulnerable` / `no_app_impact` / `unknown` | Risk **if the update is not installed** | `stays_vulnerable`: host path stays exposed; app can still run. `no_app_impact`: skipping does not change the product process (bundled runtime / no loader). Do not treat those as the same. |
| `compatibility` | `incompatible` / `compatible` / `unknown` | Does current `main` logic work with the proposed vendor bits? | `compatible`: current `main` already runs against today's host bits; cite the files you read. |

Rules:

1. **`required_for_app: required` and `skip_risk: app_will_fail`** only with a cited file that loads the patched component. "Windows has a CVE" is not enough. Current `main` has no third-party `PackageReference`; Core is `net9.0` BCL only.
2. **Self-contained publish:** an OS .NET KB almost never makes the app "not work without the KB". Say `not_required` and `skip_risk: no_app_impact` for `os-dotnet` unless you prove framework-dependent load.
3. **`install_risk: breaks_app` / `may_break_app`** when host OS/WPF/Shell/DPI/reboot would change behavior of files you read. That is incompatibility **with** the vendor update, not a reason to install it.
4. If FindUpdates is `do_not_install` / HOLD / BLOCK, keep that verdict in the Recommendation column as `Low Prio`. A high `skip_risk` does **not** override HOLD/BLOCK.
5. If you cannot match the vendor package to a library or logic path on `main`, set `required_for_app: not_required`, `skip_risk: no_app_impact`, and **do not file** unless HOLD/BLOCK must be recorded.

## Cluster before writing analysis files

Reviewers need **one card per coupling on UVCS configuration 1**, not one card per CVE and not one card per synthetic station.

A live run that produced 20 files with six repeated rationales (Schannel ×4, Win32k ×3, DWM ×2, Shell ×3, NTFS ×4, .NET ×4) is a failure of this skill.

After scoring, group rows that share **all** of:

- the same product configuration (`uvcs-configuration-1`)
- the same `cluster_key` (same cited files, same failure mode)
- the same four risk fields
- the same Recommendation (`Install - High Prio` / `Low Prio`)

Write **one** file for that group. Put every distinct Title, Package, CVE, and Recommendation in the Updates table. Dedupe identical package + CVE rows that only differ by lab `device_id`. For each row, if `official_url` is a `https://` value from that same report row, make **only Package** a markdown link (`[KB5122871](https://msrc.microsoft.com/...)`). Do not link Title or CVEs. Never invent or rewrite the URL. Technical Impact Assessment, Cybersecurity impact assessment, and Product Risk assessment are written **once** for the coupling.

Do **not** file a second analysis because:

- two rows share a KB but are different CVEs of the same component
- titles differ only by DoS / EoP / RCE / bypass on the same host stack
- `risk_score` differs while the cited files and recommendation stay the same
- lab stations differ while the product configuration is the same

Split into two files only when the **cited files** or **Install vs Low Prio recommendation** actually differ (for example HOLD vs `candidate_for_validation`, or `os-dotnet` Low Prio vs `schannel-tls` Install - High Prio).

Prefer `candidate_for_validation` when choosing which member rows to keep. File a Low Prio cluster when installing would be harmful **or** the app is explicitly not affected (`os-dotnet`) and reviewers must not treat the KB as a product patch.

Cap: at most **8** individual analysis files (one cluster × product configuration each). Overflow goes to `issues-out/summary.json`.

Skip:

- `not_in_scope` unless `main` still targets that OS/package
- Media/codec/network CVEs with no caller on `main`
- Duplicate `cluster_key` + `uvcs-configuration-1` pairs
- Files whose only evidence is "it is a Windows WPF app"
- Extra files that would repeat an already-written coupling paragraph

## Output files

`issues-out/01-<cluster_key>-uvcs-configuration-1.json`

Required keys: `title`, `body`, `advisory_id`, `device_id`, `cluster_key`, `labels`, `required_for_app`, `install_risk`, `skip_risk`, `compatibility`.

Set `advisory_id` to the same value as `cluster_key`. Set `device_id` to `uvcs-configuration-1` (product configuration id, not a lab station).

Patch name in the title: the cluster's `package` (KB) when every distinct update row shares one package; otherwise `cluster_key`.

Title format:

`[Impact] {patch name} on UVCS configuration 1 - {short description}`

`{short description}` describes the coupling, not one CVE (for example `Schannel TLS path has no defense in depth`, `Win32k may change WPF DPI`, `OS .NET KB does not patch bundled runtime`).

Labels must include `vendor-update-impact` and `product-config:uvcs-configuration-1`.

The body must follow [issue-template.md](issue-template.md), include

`<!-- impact:{cluster_key}:uvcs-configuration-1 -->`

list each product source repo with its commit under **Impact analysis conducted on source code version**, and cite **at least one path under `workspace/DesktopApplication/`** from `main` (file plus what you read there). "WPF / net9 / SBOM present" is not sufficient evidence.

Do **not** include: a GitHub issue sentence, Advisory / Policy / Score columns, an authorization disclaimer, or a Recent code section.

If nothing qualifies, write `issues-out/none.json`:

```json
{
  "issues": []
}
```

Do not include secrets, tokens, PHI, or patient identifiers. Official URLs only if already present on the report row.
