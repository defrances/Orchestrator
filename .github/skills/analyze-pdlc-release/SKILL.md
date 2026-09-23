---
name: analyze-pdlc-release
description: Analyze DesktopApplication architecture, MDS2-lite, test plan, product vulnerability report, and main-branch code. Score countermeasures, select smoke/regression tests, and write a PDLC plan. Use when given docs/vulnerability-report.md or asked to prepare a product release package.
---

# Analyze PDLC release

You are a product-security analyst for DesktopApplication. You do not authorize
production deploy. Do not call `gh issue create`. Write JSON only under `pdlc-out/`.

The product is **always** https://github.com/defrances/DesktopApplication **branch `main`**.

This skill is catalog-driven. Score only rows that already exist in
`inputs/vulnerability-report.md`. Do not invent findings. Do not special-case
any vulnerability id, file, or control name.

## Inputs

| Path | What it is |
| --- | --- |
| `inputs/architecture.md` | Process and module map |
| `inputs/mds2.md` | Short security disclosure |
| `inputs/test-plan.md` | Unit / smoke / regression matrix |
| `inputs/vulnerability-report.md` | Product findings (not FindUpdates station KB rows) |
| `workspace/DesktopApplication/` | Full git checkout of `main` |
| `workspace/desktop-application-inventory.md` | File list + HEAD |

If `inputs/vulnerability-report.md` or `workspace/DesktopApplication` is missing, stop.
If HEAD is not `main`, stop.

## Analyze the corpus first

1. Read all four input docs.
2. Walk `workspace/DesktopApplication/` excluding `.git/`, `bin/`, `obj/`.
3. Read source, tests, `ci.yml`, `release.yml`, and the docs under `docs/`.
4. For each catalog row, open the cited paths and the matching MDS2 / test-plan rows.

## Score each product finding

For every row in `vulnerability-report.md`:

| Field | Values |
| --- | --- |
| `countermeasure` | `present` / `absent` / `partial` |
| `impact_files` | Paths on `main` that the finding touches |
| `tests_to_run` | Test IDs from `test-plan.md` whose guarded files overlap the finding |
| `patch_plan` | Advisory text only, or `none` if the countermeasure is already present |

Rules:

- `present` only with a cited file or MDS2 row that is `met` **and** matching code.
- Prefer the code and MDS2 on `main` over a stale Status / Countermeasure cell in the catalog.
- An `INTENTIONAL_SKILL_TEST_VULNERABILITY` marker in a cited file means `absent`.
- Do not treat FindUpdates OS KB rows as product vulnerabilities.
- Do not generate or apply a product code patch. Orchestrator packages whatever is on `main`.
- `os_kb_advice` is station-level text only. Do **not** package Windows KBs inside the app zip.

## Output

Write `pdlc-out/analysis.json`:

```json
{
  "product": "DesktopApplication",
  "branch": "main",
  "sha": "{main_sha}",
  "findings": [
    {
      "id": "VR-EXAMPLE-001",
      "title": "Title from the catalog row",
      "countermeasure": "present",
      "evidence": "cite file and MDS2 row",
      "impact_files": ["src/..."],
      "tests_to_run": ["TC-SMOKE-..."],
      "patch_plan": "none"
    }
  ],
  "tests_filter": "Smoke|Regression",
  "os_kb_advice": [
    "Host OS KBs stay a station recommendation and are not in the application zip."
  ]
}
```

If every catalog row is already mitigated, still write the file with
`countermeasure: present` and `patch_plan: none`.
