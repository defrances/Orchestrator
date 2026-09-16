<!-- impact:{advisory_id}:{device_id} -->

Analyzed https://github.com/defrances/DesktopApplication branch `main` at `{main_sha}`.

## Update

- Advisory: `{advisory_id}`
- Title: `{title}`
- Vendor: `{vendor}`
- Package: `{package}`
- CVEs: `{cve_ids}`
- Action from FindUpdates: `{action}`
- Policy: `{policy_result}` (score `{risk_score}`, severity `{severity}`)
- Official source: `{official_url}`

This issue is **not** an authorization to install, approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.

## Workstation

- Device: `{device_id}`
- Model / role: `{model}` / `{device_role}`
- Deployment group: `{deployment_group}`
- OS: `{os_product}` build `{os_build}`
- Clinical criticality: `{clinical_criticality}`
- Network exposure: `{network_exposure}`

## Evidence from DesktopApplication main

List the files you read on `main` and the symbols or settings that connect this update to the app. Example shape:

- `src/DesktopApplication.Core/NoteStore.cs` — `%AppData%\DesktopApplication\notes.txt`
- `src/DesktopApplication/app.manifest` — `PerMonitorV2`
- `.github/workflows/ci.yml` — `dotnet publish` `--self-contained true` `-r win-x64`

Do not cite files you did not read.

## Risk to DesktopApplication on main

- Required for the app to keep working: `{required_for_app}` (`required` only if a cited library or logic path on `main` cannot run without this vendor package)
- Risk if the vendor update **is installed**: `{install_risk}` — incompatible API, ABI, WPF/DPI/reboot, or bundled runtime mismatch
- Risk if the vendor update **is not installed**: `{skip_risk}` — app fails, stays on a vulnerable library the process loads, or no app impact
- Compatibility of current `main` with the proposed bits: `{compatibility}`

Name the library or logic (csproj, SBOM package, `NoteStore`, WPF, `RuntimeInformation`). If the app does **not** load that component, say so. Do not claim "DesktopApplication will not work without this update" unless `required_for_app` is `required` and you cited the binding.

## How this can affect DesktopApplication

Explain the failure mode using those files: startup, WPF rendering, DPI, notes I/O, `RuntimeInformation` strings, reboot during a session, or a publish/SBOM mismatch. Say when the OS KB does **not** change the bundled runtime.

## Recent code on main that raises or lowers the risk

Commits on `main` that touch the cited files. If none, write `No recent main commits change this coupling.`

## Recommended reviewer action

What to verify on this station against the **current main** build. Do not instruct production install.
