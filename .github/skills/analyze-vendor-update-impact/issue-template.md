<!-- impact:{advisory_id}:{device_id} -->

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

## How this can affect DesktopApplication

Explain the plausible failure mode on **this** workstation: crash on startup, missing runtime, reboot during use, WPF rendering, single-file extraction, DPI/manifest, notes file I/O, or a SBOM package bump.

Cite evidence:

- App files or APIs (for example `src/DesktopApplication/MainWindow.xaml`, `net9.0-windows`, self-contained publish)
- SBOM / dependency names if present
- FindUpdates explanation for the station

## Recent code that raises or lowers the risk

Summarize the latest DesktopApplication commits/diffs that interact with this update (runtime, OS version assumptions, packaging, native deps). If none, say so.

## Recommended reviewer action

What a human should verify on this station before any change. Do not instruct production install.
