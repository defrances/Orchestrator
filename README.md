# Orchestrator

Cross-repository control plane for DesktopApplication.

After a successful CI run on `main` in [defrances/DesktopApplication](https://github.com/defrances/DesktopApplication), a run starts **in this repository**, then this repository starts a run **in FindUpdates**:

1. DesktopApplication [Notify Orchestrator](https://github.com/defrances/DesktopApplication/actions/workflows/notify-orchestrator.yml) sends `repository_dispatch` (`desktop-application-merged`)
2. [This workflow](https://github.com/defrances/Orchestrator/actions) starts [FindUpdates `detect.yml`](https://github.com/defrances/FindUpdates/actions/workflows/detect.yml) with **`source=live`**
3. Downloads the `findupdates-report-json` artifact (`report.json`)
4. Runs the GitHub Copilot skill `analyze-vendor-update-impact` against DesktopApplication (code, recent commits, SBOM)
5. Opens GitHub Issues in DesktopApplication for updates that may affect the app **on a specific workstation**

The analysis is advisory only. It is not an authorization to install, approve, or deploy. HOLD and BLOCK stay HOLD and BLOCK.

```mermaid
sequenceDiagram
  participant DA as DesktopApplication
  participant Orch as Orchestrator
  participant FU as FindUpdates
  participant Copilot as CopilotCLI
  DA->>DA: merge to main plus CI success
  DA->>Orch: repository_dispatch desktop-application-merged
  Note over Orch: run appears in Orchestrator Actions
  Orch->>FU: workflow_dispatch detect.yml source=live
  Note over FU: run appears in FindUpdates Actions
  FU-->>Orch: artifact findupdates-report-json
  Orch->>Copilot: skill analyze-vendor-update-impact
  Copilot-->>DA: GitHub Issues per impactful update and workstation
```

## Where each run appears

| Step | Repository | Actions URL |
| --- | --- | --- |
| Build, test, SBOM | DesktopApplication | https://github.com/defrances/DesktopApplication/actions |
| Notify Orchestrator | DesktopApplication | https://github.com/defrances/DesktopApplication/actions/workflows/notify-orchestrator.yml |
| Orchestrate (this pipeline) | Orchestrator | https://github.com/defrances/Orchestrator/actions |
| Live detect | FindUpdates | https://github.com/defrances/FindUpdates/actions/workflows/detect.yml |
| Impact issues | DesktopApplication | https://github.com/defrances/DesktopApplication/issues?q=label%3Avendor-update-impact |

## Workflows

| Workflow | Repository | Role |
| --- | --- | --- |
| [CI](https://github.com/defrances/DesktopApplication/blob/main/.github/workflows/ci.yml) | DesktopApplication | Build, test, SBOM |
| [Notify Orchestrator](https://github.com/defrances/DesktopApplication/blob/main/.github/workflows/notify-orchestrator.yml) | DesktopApplication | After successful `main` CI, start this repo |
| [Orchestrate](.github/workflows/orchestrate.yml) | Orchestrator | Dispatch FindUpdates, Copilot analysis, issue publish |
| [Detect updates](https://github.com/defrances/FindUpdates/blob/main/.github/workflows/detect.yml) | FindUpdates | Poll MSRC/Intel, station report |

## Secrets

Create a fine-grained PAT (or classic `repo` + `workflow` PAT) that can:

| Repository | Permissions |
| --- | --- |
| `defrances/Orchestrator` | Contents: **Read and write** (`repository_dispatch`), Actions: **Read and write** (`workflow_dispatch`) |
| `defrances/FindUpdates` | Actions: **Read and write** (start `detect.yml`, download artifacts) |
| `defrances/DesktopApplication` | Contents: read, Actions: read, Issues: **write** (checkout, SBOM artifact, create issues) |

Edit an existing token in place if needed: https://github.com/settings/personal-access-tokens — the secret value can stay the same.

Store it as **`ORCHESTRATOR_PAT`** in:

- [DesktopApplication secrets](https://github.com/defrances/DesktopApplication/settings/secrets/actions)
- [Orchestrator secrets](https://github.com/defrances/Orchestrator/settings/secrets/actions)

The Copilot skill step authenticates with `GITHUB_TOKEN` and `permissions: copilot-requests: write` (no PAT). Optional **`COPILOT_GITHUB_TOKEN`** overrides that if you want a user-owned fine-grained PAT with Account permission **Copilot Requests**. If Copilot CLI cannot authenticate, the workflow uses deterministic fallback analysis and still publishes Issues.

`GITHUB_TOKEN` cannot start workflows in another repository. Cross-repo dispatch and issue creation use `ORCHESTRATOR_PAT` only.

## Manual run

Actions → **Orchestrate vendor impact analysis** → **Run workflow**.

Inputs:

- `sha` — triggering DesktopApplication commit (CI correlation); analysis always uses branch `main`
- `ci_run_id` — optional CI run id, used to download the `sbom` artifact

## Copilot skill

[`.github/skills/analyze-vendor-update-impact/`](.github/skills/analyze-vendor-update-impact/)

The skill always analyzes the full [DesktopApplication `main`](https://github.com/defrances/DesktopApplication/tree/main) checkout (every source file, not only the csproj/SBOM). It reads `inputs/report.json` and writes JSON under `issues-out/`. A separate script publishes Issues so the model does not get a write token for `gh issue create`.

## Issues in DesktopApplication

Look at [DesktopApplication Issues](https://github.com/defrances/DesktopApplication/issues?q=is%3Aissue+label%3Avendor-update-impact) labeled `vendor-update-impact`.

Each issue names:

- which vendor update may affect the app
- which workstation (`device_id`, OS, role)
- evidence from recent DesktopApplication code / SBOM

At most 20 individual issues are opened per run. Overflow is one summary issue. Duplicates of an open `advisory_id` + `device_id` pair are skipped.

## Artifacts

Orchestrator uploads `orchestrator-analysis` (`inputs/report.json` and `issues-out/**`), retained 14 days. The live detect artifacts stay on the FindUpdates run.
