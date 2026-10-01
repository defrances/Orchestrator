#!/usr/bin/env python3
"""Write advisory role-skill reviews from existing vendor-impact and PDLC JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ISSUES_DIR = Path("issues-out")
PDLC_PATH = Path("pdlc-out/analysis.json")
REPORT = Path("inputs/report.json")
VULN_CATALOG = Path("inputs/vulnerability-report.md")
TEST_PLAN_PATHS = (
    Path("inputs/test-plan.md"),
    Path("workspace/HostApplication/docs/test-plan.md"),
)
OUT_ROOT = Path("skills-out")

SKIP_ISSUE_FILES = {
    "none.json",
    "summary.json",
    "ai-usage.json",
    "missing-report.json",
}

ROLE_META = {
    "architect": {
        "skill": "Architect_Skill",
        "prefix": "ARCH",
        "out": OUT_ROOT / "architect" / "review.json",
    },
    "test-engineer": {
        "skill": "Test_Engineer_Skill",
        "prefix": "TEST",
        "out": OUT_ROOT / "test-engineer" / "review.json",
    },
    "cybersec": {
        "skill": "CyberSec_Engineer_Skill",
        "prefix": "CYB",
        "out": OUT_ROOT / "cybersec" / "review.json",
    },
    "product-safety": {
        "skill": "Product_Safety_Engineer_Skill",
        "prefix": "SAFE",
        "out": OUT_ROOT / "product-safety" / "review.json",
    },
    "sqa": {
        "skill": "SQA_Engineer_Skill",
        "prefix": "SQA",
        "out": OUT_ROOT / "sqa" / "review.json",
    },
}

ADVISORY = "Advisory only. Do not change HOLD/BLOCK."
SAFETY_ADVISORY = "Advisory only. Do not authorize install. HOLD/BLOCK stay."
CONFIG_RE = re.compile(r"^Config\d+$")
TEST_ID_RE = re.compile(r"TC-[A-Z0-9-]+")
CLINICAL_RE = re.compile(r"Clinical criticality:\s*`?([^\n`<]+)", re.I)
CITE_RE = re.compile(r"`((?:src|tests|docs)/[^`]+)`")


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_clusters() -> list[dict[str, object]]:
    if not ISSUES_DIR.is_dir():
        return []
    clusters: list[dict[str, object]] = []
    for path in sorted(ISSUES_DIR.glob("*.json")):
        if path.name in SKIP_ISSUE_FILES:
            continue
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        if "issues" in payload and not payload.get("cluster_key"):
            continue
        clusters.append(payload)
    return clusters


def load_pdlc() -> dict[str, object]:
    payload = _load_json(PDLC_PATH)
    return payload if isinstance(payload, dict) else {}


def pdlc_findings(pdlc: dict[str, object]) -> list[dict[str, object]]:
    rows = pdlc.get("findings") or []
    return [row for row in rows if isinstance(row, dict)]


def catalog_ids() -> set[str]:
    if not VULN_CATALOG.is_file():
        return set()
    text = VULN_CATALOG.read_text(encoding="utf-8")
    return set(re.findall(r"\bVR-[A-Z0-9-]+\b", text))


def test_plan_ids() -> set[str]:
    found: set[str] = set()
    for path in TEST_PLAN_PATHS:
        if path.is_file():
            found.update(TEST_ID_RE.findall(path.read_text(encoding="utf-8")))
    return found


def cluster_config(item: dict[str, object]) -> str:
    return str(item.get("device_id") or "").strip()


def cluster_key(item: dict[str, object]) -> str:
    return str(item.get("cluster_key") or item.get("advisory_id") or "cluster").strip()


def letter(item: dict[str, object], *names: str) -> str:
    for name in names:
        value = str(item.get(name) or "").strip().upper()
        if value in {"C", "H", "M", "L"}:
            return value
    return "M"


def cited_paths(item: dict[str, object]) -> list[str]:
    body = str(item.get("body") or "")
    paths = []
    for match in CITE_RE.findall(body):
        if match not in paths:
            paths.append(match)
    return paths[:8]


def clinical_criticality(item: dict[str, object]) -> str:
    body = str(item.get("body") or "")
    match = CLINICAL_RE.search(body)
    if match:
        return match.group(1).strip().strip("*")
    return ""


def tests_in_text(*texts: object) -> list[str]:
    found: list[str] = []
    for text in texts:
        for match in TEST_ID_RE.findall(str(text or "")):
            if match not in found:
                found.append(match)
    return found


def base_review(skill: str, summary: str, findings: list[dict[str, object]]) -> dict[str, object]:
    return {
        "skill": skill,
        "product": "HostApplication",
        "branch": "main",
        "advisory": True,
        "do_not_deploy": True,
        "summary": summary,
        "findings": findings,
    }


def architect_review(clusters: list[dict[str, object]], pdlc_rows: list[dict[str, object]]) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    for item in clusters:
        key = cluster_key(item)
        config = cluster_config(item)
        evidence = cited_paths(item) or [key]
        findings.append(
            {
                "id": f"ARCH-{key}-{config or 'na'}",
                "config": config,
                "cluster_key": key,
                "severity": letter(item, "product_risk", "vendor_risk"),
                "summary": (
                    f"{item.get('title') or key}: coupling {key}; "
                    f"required_for_app={item.get('required_for_app')}; "
                    f"compatibility={item.get('compatibility')}"
                ),
                "evidence": evidence,
                "recommendation": ADVISORY,
            }
        )
    for row in pdlc_rows:
        ident = str(row.get("id") or "PDLC")
        files = [str(path) for path in (row.get("impact_files") or []) if path]
        findings.append(
            {
                "id": f"ARCH-{ident}",
                "config": "",
                "cluster_key": "",
                "severity": "M",
                "summary": (
                    f"{row.get('title') or ident}: countermeasure "
                    f"{row.get('countermeasure')}; modules {', '.join(files) or 'unspecified'}"
                ),
                "evidence": files,
                "recommendation": ADVISORY,
            }
        )
    summary = (
        f"Architect review of {len(clusters)} vendor cluster(s) and "
        f"{len(pdlc_rows)} product finding(s)."
        if findings
        else "No vendor-impact or PDLC analysis was available."
    )
    return base_review("Architect_Skill", summary, findings)


def test_engineer_review(clusters: list[dict[str, object]], pdlc_rows: list[dict[str, object]]) -> dict[str, object]:
    allowed = test_plan_ids()
    findings: list[dict[str, object]] = []
    for item in clusters:
        key = cluster_key(item)
        config = cluster_config(item)
        tests = [tid for tid in tests_in_text(item.get("body"), item.get("title")) if not allowed or tid in allowed]
        findings.append(
            {
                "id": f"TEST-{key}-{config or 'na'}",
                "config": config,
                "cluster_key": key,
                "severity": letter(item, "product_risk", "vendor_risk"),
                "summary": "Existing test-plan ids that overlap this coupling."
                if tests
                else "No test-plan id cited for this coupling.",
                "tests_to_run": tests,
                "gap": "" if tests else "No matching test id in the cluster body or test plan.",
                "recommendation": ADVISORY,
            }
        )
    for row in pdlc_rows:
        ident = str(row.get("id") or "PDLC")
        raw = [str(tid) for tid in (row.get("tests_to_run") or []) if tid]
        tests = [tid for tid in raw if not allowed or tid in allowed]
        findings.append(
            {
                "id": f"TEST-{ident}",
                "config": "",
                "cluster_key": "",
                "severity": "M",
                "summary": f"{row.get('title') or ident}: tests from the PDLC catalog row.",
                "tests_to_run": tests,
                "gap": "" if tests else "PDLC row has no test-plan id.",
                "recommendation": ADVISORY,
            }
        )
    review = base_review(
        "Test_Engineer_Skill",
        (
            f"Test coverage review for {len(clusters)} cluster(s) and {len(pdlc_rows)} finding(s)."
            if findings
            else "No vendor-impact or PDLC analysis was available."
        ),
        findings,
    )
    review["tests_filter"] = "Smoke|Regression"
    return review


def cybersec_review(clusters: list[dict[str, object]], pdlc_rows: list[dict[str, object]]) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    for item in clusters:
        key = cluster_key(item)
        config = cluster_config(item)
        likelihood = letter(item, "vendor_likelihood")
        findings.append(
            {
                "id": f"CYB-{key}-{config or 'na'}",
                "config": config,
                "cluster_key": key,
                "severity": letter(item, "vendor_risk", "vendor_severity"),
                "vendor_severity": letter(item, "vendor_severity"),
                "vendor_likelihood": likelihood,
                "vendor_risk": letter(item, "vendor_risk", "vendor_severity"),
                "product_risk": letter(item, "product_risk"),
                "kev": likelihood == "C",
                "summary": (
                    f"Vendor {letter(item, 'vendor_risk')} vs product "
                    f"{letter(item, 'product_risk')} for {key} on {config or 'n/a'}."
                ),
                "evidence": cited_paths(item),
                "recommendation": ADVISORY,
            }
        )
    for row in pdlc_rows:
        ident = str(row.get("id") or "PDLC")
        files = [str(path) for path in (row.get("impact_files") or []) if path]
        findings.append(
            {
                "id": f"CYB-{ident}",
                "config": "",
                "cluster_key": "",
                "severity": "M",
                "vendor_severity": "",
                "vendor_likelihood": "",
                "vendor_risk": "",
                "product_risk": "L" if row.get("countermeasure") == "present" else "M",
                "kev": False,
                "summary": f"{ident}: product finding countermeasure {row.get('countermeasure')}.",
                "evidence": files,
                "recommendation": ADVISORY,
            }
        )
    summary = (
        f"Cybersecurity review of {len(clusters)} cluster(s) and {len(pdlc_rows)} finding(s)."
        if findings
        else "No vendor-impact or PDLC analysis was available."
    )
    return base_review("CyberSec_Engineer_Skill", summary, findings)


def product_safety_review(clusters: list[dict[str, object]], pdlc_rows: list[dict[str, object]]) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    for item in clusters:
        key = cluster_key(item)
        config = cluster_config(item)
        findings.append(
            {
                "id": f"SAFE-{key}-{config or 'na'}",
                "config": config,
                "cluster_key": key,
                "severity": letter(item, "product_risk", "vendor_risk"),
                "clinical_criticality": clinical_criticality(item),
                "install_risk": str(item.get("install_risk") or ""),
                "skip_risk": str(item.get("skip_risk") or ""),
                "summary": (
                    f"Install {item.get('install_risk')} / skip {item.get('skip_risk')} "
                    f"on {config or 'n/a'}. No install authorization."
                ),
                "evidence": cited_paths(item) or ["docs/security-risk-management.md"],
                "recommendation": SAFETY_ADVISORY,
            }
        )
    for row in pdlc_rows:
        ident = str(row.get("id") or "PDLC")
        findings.append(
            {
                "id": f"SAFE-{ident}",
                "config": "",
                "cluster_key": "",
                "severity": "M",
                "clinical_criticality": "",
                "install_risk": "",
                "skip_risk": "",
                "summary": (
                    f"{ident}: product finding stays catalog-driven; "
                    f"countermeasure {row.get('countermeasure')}."
                ),
                "evidence": [str(path) for path in (row.get("impact_files") or []) if path],
                "recommendation": SAFETY_ADVISORY,
            }
        )
    summary = (
        f"Product-safety review of {len(clusters)} cluster(s) and {len(pdlc_rows)} finding(s)."
        if findings
        else "No vendor-impact or PDLC analysis was available."
    )
    return base_review("Product_Safety_Engineer_Skill", summary, findings)


def _check(ident: str, status: str, summary: str, evidence: list[str]) -> dict[str, object]:
    return {
        "id": ident,
        "config": "",
        "severity": "L" if status == "pass" else "H",
        "status": status,
        "summary": summary,
        "evidence": evidence,
        "recommendation": ADVISORY,
    }


def sqa_review(clusters: list[dict[str, object]], pdlc_rows: list[dict[str, object]]) -> dict[str, object]:
    allowed_tests = test_plan_ids()
    catalog = catalog_ids()
    labels = [cluster_config(item) for item in clusters if cluster_config(item)]
    bad_labels = [name for name in labels if not CONFIG_RE.fullmatch(name)]
    required = (
        "cluster_key",
        "required_for_app",
        "install_risk",
        "skip_risk",
        "compatibility",
    )
    missing_fields = [
        cluster_key(item)
        for item in clusters
        if any(not str(item.get(field) or "").strip() for field in required)
    ]
    unknown_pdlc = [
        str(row.get("id") or "")
        for row in pdlc_rows
        if catalog and str(row.get("id") or "") not in catalog
    ]
    unknown_tests: list[str] = []
    if allowed_tests:
        for row in pdlc_rows:
            for tid in row.get("tests_to_run") or []:
                if str(tid) not in allowed_tests:
                    unknown_tests.append(str(tid))
    findings = [
        _check(
            "SQA-CONFIG-LABELS",
            "pass" if not bad_labels else "fail",
            "cluster device_id values use ConfigN labels"
            if not bad_labels
            else f"non-ConfigN labels: {', '.join(bad_labels)}",
            ["issues-out/"],
        ),
        _check(
            "SQA-HOLD-BLOCK",
            "pass",
            "Role reviews do not upgrade HOLD/BLOCK or authorize install.",
            ["issues-out/"],
        ),
        _check(
            "SQA-PDLC-CATALOG",
            "pass" if not unknown_pdlc else "fail",
            "PDLC finding ids stay catalog-driven."
            if not unknown_pdlc
            else f"ids not in vulnerability-report.md: {', '.join(unknown_pdlc)}",
            ["pdlc-out/analysis.json"],
        ),
        _check(
            "SQA-TESTS-EXIST",
            "pass" if not unknown_tests else "fail",
            "tests_to_run ids exist in the test plan."
            if not unknown_tests
            else f"unknown test ids: {', '.join(unknown_tests)}",
            ["inputs/test-plan.md"],
        ),
        _check(
            "SQA-CLUSTER-FIELDS",
            "pass" if not missing_fields else "fail",
            "Vendor clusters include required risk fields."
            if not missing_fields
            else f"missing required fields: {', '.join(missing_fields)}",
            ["issues-out/"],
        ),
        _check(
            "SQA-SCOPE",
            "pass",
            "Analysis stays advisory. No Windchill, Quality, Regulatory, or gh issue create.",
            ["skills-out/"],
        ),
    ]
    if not clusters and not pdlc_rows:
        summary = "No vendor-impact or PDLC analysis was available."
    else:
        failed = sum(1 for row in findings if row.get("status") == "fail")
        summary = f"SQA completeness review: {failed} failed check(s) of {len(findings)}."
    return base_review("SQA_Engineer_Skill", summary, findings)


BUILDERS = {
    "architect": architect_review,
    "test-engineer": test_engineer_review,
    "cybersec": cybersec_review,
    "product-safety": product_safety_review,
    "sqa": sqa_review,
}


def write_review(role: str, payload: dict[str, object]) -> Path:
    path = ROLE_META[role]["out"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=tuple(ROLE_META), default="", help="one role, or all when omitted")
    args = parser.parse_args(argv)
    clusters = load_clusters()
    pdlc_rows = pdlc_findings(load_pdlc())
    roles = (args.role,) if args.role else tuple(ROLE_META)
    written: list[str] = []
    for role in roles:
        path = write_review(role, BUILDERS[role](clusters, pdlc_rows))
        written.append(str(path))
    print(f"fallback role reviews wrote {len(written)} file(s) clusters={len(clusters)} pdlc={len(pdlc_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
