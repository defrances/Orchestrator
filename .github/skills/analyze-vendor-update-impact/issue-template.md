<!-- impact:{cluster_key}:{config_label} -->

Impact analysis conducted on source code version:

- https://github.com/{repo} - commit `{sha}`

Add one list row per product source repository that was checked out for this analysis. Do not list FindUpdates or Orchestrator. Do not invent a commit.

## Updates applicable for this product configuration

| Title | Package | CVEs | Recommendation |
| --- | --- | --- | --- |
| `{title}` | [`{package}`]({official_url}) | `{cve_ids}` | `{recommendation}` |

Add one table row per distinct vendor update (dedupe the same package + CVEs across lab stations). When `official_url` is present on that report row and starts with `https://`, wrap **only Package** as a markdown link. Leave Title, CVEs, and Recommendation as plain text. If `official_url` is missing, keep Package as plain text. Do not invent URLs. Do not use `http://` or non-vendor hosts.

Map FindUpdates `action` to Recommendation display only (do not rewrite `report.json`):

- `candidate_for_validation` (and not HOLD/BLOCK) → `Install - High Prio`
- `do_not_install`, HOLD, BLOCK, `not_in_scope` → `Low Prio`

## Product Configuration Specification

- Product configuration: `{config_label}` (`Config1`, `Config2`, … — never a synthetic station id)
- Model / role: `{model}` / `{device_role}`
- Deployment group: `{deployment_group}`
- OS: `{os_product}` build `{os_build}`
- Clinical criticality: `{clinical_criticality}`
- Network exposure: `{network_exposure}`

## Vendor vs product scores

| | Severity | Likelihood | Risk |
| --- | --- | --- | --- |
| Vendor | `{C\|H\|M\|L}` | `{C\|H\|M\|L}` | `{C\|H\|M\|L}` |
| Product | `{C\|H\|M\|L}` | `{C\|H\|M\|L}` | `{C\|H\|M\|L}` |

Vendor severity is FindUpdates/MSRC. Vendor likelihood: KEV → C, high exploitability → H, unknown → M, low/none → L. Product letters may be **lower** than vendor when the published exe does not load the patched component (`no_app_impact` → product risk L). Do not invent CIA 0–5 scores.

Do not put synthetic station ids in the subject. Use the numbered label (`Config1`). If several report rows share this numbered configuration, summarize shared OS / role values instead of listing each device.

## Technical Impact Assessment

### Impacted Components

Name the product files, libraries, or host components this patch can touch. Cite paths you actually read on `main`. If the product does not load the patched component, say so.

### Potential Risks

Do **not** leave a bare enum (`not_required`, `stays_vulnerable`). Each line is **human label + why + evidence** from files, SBOM, or publish settings you actually read.

| JSON value | Label to print |
| --- | --- |
| `required` | Required |
| `not_required` | Not required |
| `breaks_app` | App may stop working |
| `may_break_app` | App may break |
| `compatible` | Compatible with the app |
| `app_will_fail` | App will fail |
| `stays_vulnerable` | Station stays exposed |
| `no_app_impact` | No effect on the app |
| `incompatible` | Not compatible |
| `unknown` | Unknown |

Shape:

- **Required for the app to keep working: {label}.** {why with cited file/SBOM/publish fact}
- **If we install: {label}.** {why}
- **If we skip: {label}.** {why}
- **Compatibility: {label}.** {why}

Why rules:

- `not_required`: say the published exe still starts without this KB, and why (no matching `PackageReference`, self-contained publish, or the patched library is not loaded).
- `required`: name the loader file that cannot run without this vendor package.
- `stays_vulnerable`: host path stays exposed; the app can still run. Name the host component and the product file that uses it.
- `no_app_impact`: skipping does not change the product process. Say why (usually bundled runtime / no loader).
- `compatible` (install or compatibility): current `main` already runs with today's host bits; installing does not replace the exe.
- `may_break_app` / `breaks_app`: name the WPF/DPI/Shell/reboot path that can change.
- `unknown`: say what you could not prove. Do not invent a loader.

### Conclusions

One coupling conclusion for the whole table. Do not repeat it once per CVE. Say when an OS KB does **not** change the bundled runtime.

## Cybersecurity impact assessment

Cover:

- which vulnerabilities this patch addresses
- which library or other dependency those CVEs sit in
- whether SBOM scan **and** source code scan show that dependency in this product

Write in this shape:

- No dependency: `This patch fixes {CVE} in {library} {version}. SBOM scan and source code scan revealed there is no such dependency in our code. This patch will not affect our product.`
- Dependency present: `This patch fixes {CVE} in {library} {version}. SBOM scan and source code scan revealed that {module} has such dependency.`

A SBOM row alone is not enough. Name the file or module, or state that none exists.

## Product Risk assessment

- Which product functions are affected (bulletin HTTPS check, notes, UI, launch, none)
- Potential hazards, if any; write `None identified for this product configuration` when the patched component is not loaded
- Failure scenarios for install vs skip

## Test Planning

Map impact onto `docs/test-plan.md`. Do not invent UI or clinical protocol tests that are not in that file.

### Recommended Regression Suite

- `{TC-id}` — one existing test per line. If none map, write `None. No documented test covers this coupling.`

### Gap Analysis

- Coverage gaps (for example no UI automation). If there is no gap, write `None identified.`

## Recommendation

Lab check vs hold, in product language. Use `Install - High Prio` or `Low Prio` consistently with the table. Do not instruct production install.
