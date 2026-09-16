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

## How this can affect DesktopApplication

Explain the failure mode using those files: startup, WPF rendering, DPI, notes I/O, `RuntimeInformation` strings, reboot during a session, or a publish/SBOM mismatch. Say when the OS KB does **not** change the bundled runtime.

## Recent code on main that raises or lowers the risk

Commits on `main` that touch the cited files. If none, write `No recent main commits change this coupling.`

## Recommended reviewer action

What to verify on this station against the **current main** build. Do not instruct production install.
