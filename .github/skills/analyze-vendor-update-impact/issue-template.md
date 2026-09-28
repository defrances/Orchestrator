<!-- impact:{cluster_key}:uvcs-configuration-1 -->

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

- Product configuration: UVCS configuration 1
- Model / role: `{model}` / `{device_role}`
- Deployment group: `{deployment_group}`
- OS: `{os_product}` build `{os_build}`
- Clinical criticality: `{clinical_criticality}`
- Network exposure: `{network_exposure}`

Do not put synthetic station ids in the subject. If several lab stations share this configuration, summarize shared OS / role values instead of listing each device.

## Technical Impact Assessment

### Components

Name the product files, libraries, or host components this patch can touch. Cite paths you actually read on `main`. If the product does not load the patched component, say so.

### Risks

- Required for the app to keep working: `{required_for_app}`
- If we install: `{install_risk}`
- If we skip: `{skip_risk}`
- Compatibility: `{compatibility}`

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

## TEST PLANNING & COVERAGE ANALYSIS

This section:

- Analyzes the technical and risk impact from the previous sections
- Defines the regression scope and maps impact onto existing Unit, Smoke, and Regression tests in `docs/test-plan.md`
- Identifies coverage gaps and the additional cases needed to close them
- Produces the test recommendation aligned to the quarterly release cadence

Recommend the existing `TC-*` ids that should be run. If no automated or documented test covers the coupling, state the gap. Do not invent UI or clinical protocol tests that are not in `docs/test-plan.md`.

## Recommendation

Lab check vs hold, in product language. Use `Install - High Prio` or `Low Prio` consistently with the table. Do not instruct production install.
