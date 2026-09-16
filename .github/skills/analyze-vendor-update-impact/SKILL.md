---
name: analyze-vendor-update-impact
description: Analyze FindUpdates station report JSON against the full DesktopApplication main branch, score install vs skip risk (library and logic compatibility), then write GitHub issue payloads. Use when given findupdates-report-json, report.json, workstation recommendations, or asked to open DesktopApplication impact issues.
---

# Analyze vendor update impact

You are an advisory analyst. You do not authorize install, approval, or deploy.
HOLD and BLOCK stay HOLD and BLOCK. Do not call `gh issue create`.
Write JSON files only under `issues-out/`.

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
   - `tests/DesktopApplication.Tests/DesktopApplication.Tests.csproj`
   - `tests/DesktopApplication.Tests/NoteStoreTests.cs`
   - `tests/DesktopApplication.Tests/SystemInformationProviderTests.cs`
4. From those files, extract facts (cite path + symbol), including:
   - Target framework, `UseWPF`, `OutputType=WinExe`, project references
   - Self-contained `win-x64` publish and SBOM generation in CI (not assumed from memory)
   - `app.manifest`: Windows 10 compatibility GUID, `dpiAware`, `PerMonitorV2`
   - UI/view-model behavior in `MainWindow` / `MainViewModel`
   - `%AppData%\DesktopApplication\notes.txt` via `NoteStore`
   - OS/user/machine/runtime strings via `SystemInformationProvider` (`RuntimeInformation`)
   - Tests that lock file I/O and OS information contracts
5. History on **main only**: `git -C workspace/DesktopApplication log --oneline -20` and diffs that change runtime, packaging, I/O, WPF, or OS assumptions.
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

After the full-repo pass, group remaining rows by `advisory_id`. Stations are context for where the **already-understood** app would run.

## Coupling to this codebase

DesktopApplication on `main` is a small self-contained WPF client. OS vendor rows are in scope only when you can name a **file on main** that would feel the change.

Typical couplings from this repo (use only if the file supports it):

- Host WPF / windowing / DPI → `MainWindow.xaml`, `app.manifest`, `UseWPF`
- Bundled .NET display / process arch → `SystemInformation.cs`, publish in `ci.yml`, SBOM runtime packs
- Local notes I/O after reboot or profile restore → `NoteStore.cs`, tests
- Shell launch / icon / exe identity → `OutputType=WinExe`, `app.manifest` assembly identity

Do **not** claim an OS .NET / .NET Framework KB patches the runtime inside the published exe unless you show the publish is framework-dependent. On current `main`, CI publishes `--self-contained true` for `win-x64`.

## Score the risk of this update

After the full-repo pass, score **both directions** for every row you might file. The question is not only "does this CVE sound serious". It is whether **this codebase on `main`** needs the update, survives the update, or breaks because of it.

Look for a real library or logic path:

- `PackageReference` / `ProjectReference` in `*.csproj`
- packages in the SBOM that the published exe actually embeds
- BCL / WPF / Win32 APIs the `.cs` / `.xaml` files call (`NoteStore` file I/O, `RuntimeInformation`, WPF types, `app.manifest` DPI)
- tests that freeze those contracts

Then assign:

| Field | Allowed values | Meaning |
| --- | --- | --- |
| `required_for_app` | `required` / `not_required` / `unknown` | `required` only if the app on `main` will fail, refuse to start, or stay on a library version the code cannot run without this vendor package |
| `install_risk` | `breaks_app` / `may_break_app` / `compatible` / `unknown` | Risk **if the vendor update is installed** on the station: API/ABI/behavior mismatch with code or bundled libs |
| `skip_risk` | `app_will_fail` / `stays_vulnerable` / `no_app_impact` / `unknown` | Risk **if the update is not installed**: missing patched library the code loads, or no path to this app |
| `compatibility` | `incompatible` / `compatible` / `unknown` | Does current `main` logic work with the proposed vendor bits? |

Rules:

1. **`required_for_app: required` and `skip_risk: app_will_fail`** only with a cited file that loads the patched component (PackageReference, SBOM package + publish embedding, or a runtime the process actually binds). "Windows has a CVE" is not enough. Current `main` has no third-party `PackageReference`; Core is `net9.0` BCL only. Do not invent NuGet deps.
2. **Self-contained publish:** an OS .NET / .NET Framework KB almost never makes the app "not work without the KB". The exe already carries `Microsoft.NETCore.App` / `Microsoft.WindowsDesktop.App` from publish. Say `not_required` unless you prove framework-dependent load.
3. **`install_risk: breaks_app` / `may_break_app`** when host OS/WPF/ALPC/Shell/DPI/reboot would change behavior of files you read (`MainWindow.xaml`, `app.manifest`, `NoteStore.cs`, `ci.yml` publish). That is incompatibility **with** the vendor update, not a reason to install it.
4. If FindUpdates is `do_not_install` / HOLD / BLOCK, keep that verdict. A high `skip_risk` does **not** override HOLD/BLOCK and must not recommend production install.
5. If you cannot match the vendor package to a library or logic path on `main`, set `required_for_app: not_required`, `skip_risk: no_app_impact` (or `unknown`), and either skip the issue or file only for host/reboot coupling with `install_risk` explained.

Put the four fields in the JSON payload **and** in the issue body (see the template). Title `{short risk}` must reflect the worse of install vs skip (for example `may break WPF DPI` or `OS KB does not patch bundled runtime`).

Skip:

- `not_in_scope` unless `main` still targets that OS/package
- Media/codec/network CVEs with no caller on `main`
- Duplicate `advisory_id` + `device_id` pairs
- Issues whose only evidence is "it is a Windows WPF app"

Prefer `candidate_for_validation` and high `risk_score`. File HOLD/BLOCK only when installing would be harmful **and** a file on `main` is implicated. The issue must say do not install.

Cap: at most 20 individual issue files. Overflow goes to `issues-out/summary.json`.

## Output files

`issues-out/01-<advisory_id>-<device_id>.json`

Required keys: `title`, `body`, `advisory_id`, `device_id`, `labels`, `required_for_app`, `install_risk`, `skip_risk`, `compatibility`.

Title format:

`[Impact] {advisory_id} on {device_id} — {short risk}`

Labels must include `vendor-update-impact` and `workstation:{device_id}`.

The body must follow [issue-template.md](issue-template.md), include

`<!-- impact:{advisory_id}:{device_id} -->`

and cite **at least one path under `workspace/DesktopApplication/`** from `main` (file plus what you read there). "WPF / net9 / SBOM present" is not sufficient evidence.

If nothing qualifies, write `issues-out/none.json`:

```json
{
  "issues": []
}
```

Do not include secrets, tokens, PHI, or patient identifiers. Official URLs only if already present on the report row.
