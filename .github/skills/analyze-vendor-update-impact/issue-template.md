<!-- impact:{cluster_key}:{device_id} -->

Analyzed https://github.com/defrances/DesktopApplication branch `main` at `{main_sha}`.

## Updates in this cluster

One GitHub issue for this coupling on this workstation. Do not open a second issue per CVE.

| Advisory | Title | Package | CVEs | Action | Policy | Score |
| --- | --- | --- | --- | --- | --- | --- |
| `{advisory_id}` | `{title}` | `{package}` | `{cve_ids}` | `{action}` | `{policy_result}` | `{risk_score}` |

Add one table row per clustered report row. Official URLs only if present on those rows.

This issue is **not** an authorization to install, approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.

## Workstation

- Device: `{device_id}`
- Model / role: `{model}` / `{device_role}`
- Deployment group: `{deployment_group}`
- OS: `{os_product}` build `{os_build}`
- Clinical criticality: `{clinical_criticality}`
- Network exposure: `{network_exposure}`

## Evidence from DesktopApplication main

List the files you read on `main` and the symbols or settings that connect **this cluster** to the app. Example shape:

- `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` — `AcceptAnyServerCertificate`
- `src/DesktopApplication.Core/NoteStore.cs` — `%AppData%\DesktopApplication\notes.txt`
- `src/DesktopApplication/app.manifest` — `PerMonitorV2`
- `.github/workflows/ci.yml` — `dotnet publish` `--self-contained true` `-r win-x64`

Do not cite files you did not read.

## Risk to DesktopApplication on main

- Required for the app to keep working: `{required_for_app}` (`required` only if a cited library or logic path on `main` cannot run without these vendor packages)
- Risk if the vendor updates **are installed**: `{install_risk}` — incompatible API, ABI, WPF/DPI/reboot, or bundled runtime mismatch
- Risk if the vendor updates **are not installed**: `{skip_risk}` — app fails, stays on a vulnerable library the process loads, or no app impact
- Compatibility of current `main` with the proposed bits: `{compatibility}`

Name the library or logic (csproj, SBOM package, `NoteStore`, WPF, `InsecureVendorBulletinClient`, `RuntimeInformation`). If the app does **not** load that component, say so. Do not claim "DesktopApplication will not work without this update" unless `required_for_app` is `required` and you cited the binding.

## How this can affect DesktopApplication

Write **one** failure-mode paragraph for the coupling. Do not repeat it once per CVE. Say when the OS KB does **not** change the bundled runtime.

## Recent code on main that raises or lowers the risk

Commits on `main` that touch the cited files. If none, write `No recent main commits change this coupling.`

## Recommended reviewer action

What to verify on this station against the **current main** build for this cluster. Do not instruct production install.
