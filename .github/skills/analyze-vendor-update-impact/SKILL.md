---
name: analyze-vendor-update-impact
description: Analyze FindUpdates station report JSON against DesktopApplication code and SBOM, then write GitHub issue payloads for vendor updates that may affect the app on a specific workstation. Use when given findupdates-report-json, report.json, workstation recommendations, or asked to open DesktopApplication impact issues.
---

# Analyze vendor update impact

You are an advisory analyst. You do not authorize install, approval, or deploy.
HOLD and BLOCK stay HOLD and BLOCK. Do not call `gh issue create`.
Write JSON files only under `issues-out/`.

## Inputs

| Path | What it is |
| --- | --- |
| `inputs/report.json` | FindUpdates `findupdates-report-json` (`kind=station_report`) |
| `workspace/DesktopApplication/` | Checkout of https://github.com/defrances/DesktopApplication |
| `workspace/sbom/DesktopApplication.sbom.spdx.json` | Optional SPDX SBOM from the triggering CI run |

If `inputs/report.json` is missing, stop.

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

Group `items` by `device_id` first. Typical stations: `SYNTHETIC-CT-IMG-01`, `SYNTHETIC-MR-IMG-01`, `SYNTHETIC-PACS-01`, `SYNTHETIC-US-01`, `SYNTHETIC-LAB-24H2-01`, `SYNTHETIC-WKLIST-01`, `SYNTHETIC-W11-24H2-01`.

## Analyze DesktopApplication

Inspect the checkout thoroughly:

1. Solution layout, WPF/.NET target (`net9.0-windows`), self-contained `win-x64` publish.
2. Recent commits: `git -C workspace/DesktopApplication log --oneline -20` and the latest merge/CI SHA.
3. Runtime and OS coupling: .NET 9, WPF, Windows 10/11, DPI manifest, single-file publish.
4. SBOM packages if present (especially Microsoft.NETCore.App, WindowsBase, PresentationFramework, runtime packs).
5. Anything in recent diffs that would break if the OS, .NET runtime, GPU/CPU microcode, or reboot behavior changes.

DesktopApplication is a Windows WPF desktop client. Vendor rows that touch Windows, .NET, Visual C++ runtime, Intel CPU/firmware on the same architecture, or force reboot are in scope. Rows that are `not_in_scope` for a station are not impact issues unless recent code still assumes that OS/package.

## Decide what becomes an issue

Create an issue payload only when **all** are true:

1. The row can affect DesktopApplication on that workstation (runtime, OS, reboot, graphics/input stack, or a package listed in the SBOM).
2. You can name the station (`device_id`) and the update (`advisory_id` / package).
3. You can point to app evidence (file, dependency, SBOM package, or recent commit).

Skip:

- `not_in_scope` unless the app clearly still targets that OS/package.
- Duplicate `advisory_id` + `device_id` pairs.
- Generic CVEs with no path to this WPF app.

Prefer `candidate_for_validation` and high `risk_score`. `do_not_install` / HOLD / BLOCK may still be filed if installing would be harmful **and** the app would be affected; the issue must say do not install.

Cap: at most 20 individual issue files. If more qualify, also write `issues-out/summary.json` listing the overflow titles.

## Output files

Write one JSON object per issue:

`issues-out/01-<advisory_id>-<device_id>.json`

Required keys: `title`, `body`, `advisory_id`, `device_id`, `labels`.

Title format:

`[Impact] {advisory_id} on {device_id} — {short risk}`

Labels must include `vendor-update-impact` and `workstation:{device_id}`.

The body must follow [issue-template.md](issue-template.md) and include this exact HTML comment on its own line:

`<!-- impact:{advisory_id}:{device_id} -->`

If nothing qualifies, write `issues-out/none.json`:

```json
{
  "issues": []
}
```

Do not include secrets, tokens, PHI, or patient identifiers. Official URLs only if already present on the report row.
