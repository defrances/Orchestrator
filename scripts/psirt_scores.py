#!/usr/bin/env python3
"""PSIRT letter scores: vendor vs product, C/H/M/L/NA.

Vendor letters come from FindUpdates severity, KEV, and exploitability.
Product letters come from Orchestrator coupling scores and are allowed to
drop below vendor (for example no_app_impact → product risk L).
"""

from __future__ import annotations

LETTER_RANK = {"NA": 0, "L": 1, "M": 2, "H": 3, "C": 4}

# Severity rows × likelihood columns, both in C/H/M/L. Mirrors the template
# matrix: Critical × Low stays Medium, not Critical.
_RISK_MATRIX = {
    ("C", "C"): "C",
    ("C", "H"): "H",
    ("C", "M"): "H",
    ("C", "L"): "M",
    ("H", "C"): "C",
    ("H", "H"): "H",
    ("H", "M"): "M",
    ("H", "L"): "M",
    ("M", "C"): "H",
    ("M", "H"): "M",
    ("M", "M"): "M",
    ("M", "L"): "L",
    ("L", "C"): "H",
    ("L", "H"): "M",
    ("L", "M"): "L",
    ("L", "L"): "L",
}


def letter_severity(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "c"}:
        return "C"
    if text in {"high", "important", "h"}:
        return "H"
    if text in {"medium", "moderate", "m"}:
        return "M"
    if text in {"low", "very low", "none", "l"}:
        return "L"
    return "NA"


def vendor_likelihood(known_exploited: object = None, exploitability: object = None) -> str:
    kev = str(known_exploited or "").strip().lower()
    if kev in {"true", "yes", "1"}:
        return "C"
    exp = str(exploitability or "").strip().lower()
    if exp == "high":
        return "H"
    if exp in {"medium", "moderate"}:
        return "M"
    if exp in {"low", "none"}:
        return "L"
    if not exp or exp == "unknown":
        return "M"
    return "M"


def overall_risk(severity: str, likelihood: str) -> str:
    if severity == "NA" or likelihood == "NA" or not severity or not likelihood:
        return "NA"
    return _RISK_MATRIX.get((severity, likelihood), "M")


def worst_letter(values: list[str] | tuple[str, ...] | None) -> str:
    letters = [item for item in (values or []) if item]
    if not letters:
        return "NA"
    return max(letters, key=lambda item: LETTER_RANK.get(item, 0))


def vendor_scores(
    *,
    severity: object = None,
    known_exploited: object = None,
    exploitability: object = None,
    risk_score: object = None,
) -> dict[str, str]:
    del risk_score
    sev = letter_severity(severity)
    lik = vendor_likelihood(known_exploited, exploitability)
    if sev == "NA":
        return {"severity": "NA", "likelihood": "NA", "risk": "NA"}
    return {"severity": sev, "likelihood": lik, "risk": overall_risk(sev, lik)}


def product_scores(
    *,
    required_for_app: object = None,
    install_risk: object = None,
    skip_risk: object = None,
    compatibility: object = None,
) -> dict[str, str]:
    del compatibility
    required = str(required_for_app or "").strip()
    install = str(install_risk or "").strip()
    skip = str(skip_risk or "").strip()
    if required == "required" or skip == "app_will_fail":
        sev, lik = "C", "H"
    elif skip == "no_app_impact":
        sev, lik = "L", "L"
    elif skip == "stays_vulnerable":
        sev, lik = "M", "M"
    elif install in {"may_break_app", "breaks_app"}:
        sev, lik = "M", "L"
    elif required == "not_required":
        sev, lik = "L", "L"
    else:
        sev, lik = "NA", "NA"
    if skip == "no_app_impact":
        return {"severity": "L", "likelihood": "L", "risk": "L"}
    if sev == "NA":
        return {"severity": "NA", "likelihood": "NA", "risk": "NA"}
    return {"severity": sev, "likelihood": lik, "risk": overall_risk(sev, lik)}


def scores_from_members(
    members: list[dict[str, object]] | None,
    *,
    required_for_app: object = None,
    install_risk: object = None,
    skip_risk: object = None,
    compatibility: object = None,
) -> dict[str, str]:
    vendor_bits = [
        vendor_scores(
            severity=item.get("severity"),
            known_exploited=item.get("known_exploited"),
            exploitability=item.get("exploitability"),
            risk_score=item.get("risk_score"),
        )
        for item in members or []
        if isinstance(item, dict)
    ]
    vendor = {
        "severity": worst_letter([item["severity"] for item in vendor_bits]),
        "likelihood": worst_letter([item["likelihood"] for item in vendor_bits]),
        "risk": worst_letter([item["risk"] for item in vendor_bits]),
    }
    product = product_scores(
        required_for_app=required_for_app,
        install_risk=install_risk,
        skip_risk=skip_risk,
        compatibility=compatibility,
    )
    return {
        "vendor_severity": vendor["severity"],
        "vendor_likelihood": vendor["likelihood"],
        "vendor_risk": vendor["risk"],
        "product_severity": product["severity"],
        "product_likelihood": product["likelihood"],
        "product_risk": product["risk"],
    }


def cell_label(vendor_risk: str, product_risk: str, *, applicable: bool) -> str:
    if not applicable:
        return "NA"
    return f"{vendor_risk} / {product_risk}"


def kb_config_matrix(
    packages: list[dict[str, object]] | None,
    config_labels: dict[str, str] | None,
    clusters: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    labels = config_labels or {}
    columns = sorted(set(labels.values()), key=_config_index)
    product_by = {}
    for cluster in clusters or []:
        if not isinstance(cluster, dict):
            continue
        config_raw = str(cluster.get("device_id") or "").strip()
        config = labels.get(config_raw, str(cluster.get("config_label") or config_raw).strip())
        product = product_scores(
            required_for_app=cluster.get("required_for_app"),
            install_risk=cluster.get("install_risk"),
            skip_risk=cluster.get("skip_risk"),
            compatibility=cluster.get("compatibility"),
        )
        for kb in cluster.get("packages") or []:
            key = str(kb or "").strip()
            if key and config:
                product_by[(key, config)] = product["risk"]
    rows = []
    for index, item in enumerate(packages or []):
        if not isinstance(item, dict):
            continue
        kb = str(item.get("kb") or item.get("package") or f"row-{index}").strip()
        stations = [str(name).strip() for name in (item.get("stations") or []) if str(name).strip()]
        applicable = {labels.get(name, name) for name in stations}
        vendor = vendor_scores(
            severity=item.get("severity"),
            known_exploited=item.get("known_exploited"),
            exploitability=item.get("exploitability"),
        )
        cells = []
        for column in columns:
            if column not in applicable:
                cells.append("NA")
                continue
            product_risk = product_by.get((kb, column), "—")
            cells.append(cell_label(vendor["risk"], str(product_risk), applicable=True))
        rows.append({"kb": kb, "cells": cells})
    return {"columns": columns, "rows": rows}


def _config_index(label: str) -> int:
    digits = "".join(ch for ch in (label or "") if ch.isdigit())
    return int(digits) if digits else 0
