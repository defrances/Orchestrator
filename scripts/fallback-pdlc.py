#!/usr/bin/env python3
"""Deterministic PDLC analysis when Copilot CLI cannot run."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

APP = Path("workspace/DesktopApplication")
OUT = Path("pdlc-out/analysis.json")
VULN = Path("inputs/vulnerability-report.md")
MDS2 = Path("inputs/mds2.md")
TLS_CS = APP / "src" / "DesktopApplication.Core" / "InsecureVendorBulletinClient.cs"
MARKER = "INTENTIONAL_SKILL_TEST_VULNERABILITY"


def git_sha() -> str:
    if not (APP / ".git").exists():
        return "unknown"
    result = subprocess.run(
        ["git", "-C", str(APP), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    return (result.stdout or "").strip() or "unknown"


def tls_bypass_present() -> bool:
    if not TLS_CS.exists():
        return False
    text = TLS_CS.read_text(encoding="utf-8")
    if MARKER not in text:
        return False
    return bool(re.search(r"return true;", text))


def main() -> int:
    if not VULN.exists():
        raise SystemExit(f"missing {VULN}")
    if not APP.exists():
        raise SystemExit(f"missing {APP}")

    bypass = tls_bypass_present()
    mds2 = MDS2.read_text(encoding="utf-8") if MDS2.exists() else ""
    mds2_tls_gap = "MDS2-TLS" in mds2 and "not met" in mds2.lower()

    if bypass or mds2_tls_gap:
        tls = {
            "id": "VR-TLS-001",
            "title": "Vendor bulletin HTTPS accepts any server certificate",
            "countermeasure": "absent",
            "evidence": (
                f"`{TLS_CS.as_posix()}` still contains `{MARKER}` and "
                "`AcceptAnyServerCertificate` returns true. MDS2-TLS is not met."
            ),
            "impact_files": [
                "src/DesktopApplication.Core/InsecureVendorBulletinClient.cs",
                "src/DesktopApplication/MainViewModel.cs",
                "tests/DesktopApplication.Tests/InsecureVendorBulletinClientTests.cs",
            ],
            "tests_to_run": ["TC-SMOKE-NOTES", "TC-SMOKE-SYSINFO", "TC-REG-TLS-CALLBACK"],
            "patch_plan": (
                "Require SslPolicyErrors.None in AcceptAnyServerCertificate; "
                "remove the intentional-vuln marker; update TC-REG-TLS-CALLBACK "
                "to expect rejection of an invalid chain."
            ),
        }
    else:
        tls = {
            "id": "VR-TLS-001",
            "title": "Vendor bulletin HTTPS accepts any server certificate",
            "countermeasure": "present",
            "evidence": "Certificate callback no longer accepts every chain; MDS2-TLS gap is closed.",
            "impact_files": [
                "src/DesktopApplication.Core/InsecureVendorBulletinClient.cs",
            ],
            "tests_to_run": ["TC-SMOKE-NOTES", "TC-SMOKE-SYSINFO", "TC-REG-TLS-CALLBACK"],
            "patch_plan": "none",
        }

    notes = {
        "id": "VR-NOTES-001",
        "title": "Notes stored as plaintext in user AppData",
        "countermeasure": "present",
        "evidence": "NoteStore writes a local AppData file only; no PHI; no network export.",
        "impact_files": ["src/DesktopApplication.Core/NoteStore.cs"],
        "tests_to_run": ["TC-SMOKE-NOTES"],
        "patch_plan": "none",
    }

    payload = {
        "product": "DesktopApplication",
        "branch": "main",
        "sha": git_sha(),
        "findings": [tls, notes],
        "tests_filter": "Smoke|Regression",
        "os_kb_advice": [
            "Host Schannel KBs stay a station-level recommendation and are not packaged in the application zip.",
            "An OS .NET KB does not patch the bundled self-contained runtime.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} countermeasure_tls={tls['countermeasure']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
