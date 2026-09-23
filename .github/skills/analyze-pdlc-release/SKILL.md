---
name: analyze-pdlc-release
description: Analyze DesktopApplication architecture, MDS2-lite, test plan, product vulnerability report, and main-branch code. Score countermeasures, select smoke/regression tests, and write a PDLC patch plan. Use when given docs/vulnerability-report.md or asked to prepare a product patch and release package.
---

# Analyze PDLC release

You are a product-security analyst for DesktopApplication. You do not authorize
production deploy. Do not call `gh issue create`. Write JSON only under `pdlc-out/`.

The product is **always** https://github.com/defrances/DesktopApplication **branch `main`**.

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
4. Confirm whether `InsecureVendorBulletinClient.AcceptAnyServerCertificate` still returns `true` and whether `INTENTIONAL_SKILL_TEST_VULNERABILITY` is present.

## Score each product finding

For every row in `vulnerability-report.md`:

| Field | Values |
| --- | --- |
| `countermeasure` | `present` / `absent` / `partial` |
| `impact_files` | Paths on `main` that the finding touches |
| `tests_to_run` | Test IDs from `test-plan.md` |
| `patch_plan` | Concrete change, or `none` if countermeasure is already present |

Rules:

- `present` only with a cited file or MDS2 row that is `met` **and** matching code.
- TLS trust-all (`AcceptAnyServerCertificate` always `true`, or MDS2-TLS `not met`) is `absent`.
- Local notes without PHI is `present` for VR-NOTES-001 in this PoC.
- Do not treat FindUpdates OS KB rows as product vulnerabilities.
- `os_kb_advice` is station-level text only. Do **not** package Windows KBs.

## Output

Write `pdlc-out/analysis.json`:

```json
{
  "product": "DesktopApplication",
  "branch": "main",
  "sha": "{main_sha}",
  "findings": [
    {
      "id": "VR-TLS-001",
      "title": "Vendor bulletin HTTPS accepts any server certificate",
      "countermeasure": "absent",
      "evidence": "cite file + MDS2-TLS",
      "impact_files": [
        "src/DesktopApplication.Core/InsecureVendorBulletinClient.cs",
        "src/DesktopApplication/MainViewModel.cs"
      ],
      "tests_to_run": ["TC-SMOKE-NOTES", "TC-SMOKE-SYSINFO", "TC-REG-TLS-CALLBACK"],
      "patch_plan": "Require SslPolicyErrors.None; update TC-REG-TLS-CALLBACK to expect rejection"
    }
  ],
  "tests_filter": "Smoke|Regression",
  "os_kb_advice": [
    "Host Schannel KBs stay a station recommendation and are not in the application zip."
  ]
}
```

If nothing in the report needs a product patch, still write the file with
`countermeasure: present` and `patch_plan: none`.
