#!/usr/bin/env python3
"""Email Orchestrator results via Gmail SMTP. Never logs the password."""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from pathlib import Path

DEFAULT_MAIL = "andrey02061987@gmail.com"
FINDUPDATES_REPO = os.environ.get("FINDUPDATES_REPO", "defrances/FindUpdates")


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _never_log_secret(value: str) -> None:
    del value


def load_analysis_summaries(directory: Path) -> list[str]:
    lines: list[str] = []
    if not directory.is_dir():
        return ["No analysis files under issues-out/."]
    files = sorted(directory.glob("*.json"))
    if not files:
        return ["No analysis JSON files under issues-out/."]
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            lines.append(f"- {path.name}: (invalid JSON)")
            continue
        items: list[object]
        if isinstance(data, dict) and isinstance(data.get("issues"), list):
            items = data["issues"]
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            if "token" in item:
                lines.append(f"- {path.name}: refused (token field)")
                continue
            title = str(item.get("title") or path.name).strip()
            device = str(item.get("device_id") or "").strip()
            cluster = str(item.get("cluster_key") or item.get("advisory_id") or "").strip()
            extra = " / ".join(part for part in (cluster, device) if part)
            lines.append(f"- {title}" + (f" ({extra})" if extra else ""))
    return lines or ["Analysis JSON contained no titled items."]


def desktop_sha(app_dir: Path) -> str:
    head = app_dir / ".git" / "HEAD"
    if not (app_dir / ".git").exists():
        return "(DesktopApplication checkout not available)"
    import subprocess

    result = subprocess.run(
        ["git", "-C", str(app_dir), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    sha = (result.stdout or "").strip()
    if result.returncode != 0 or not sha:
        del head
        return "(unable to read DesktopApplication HEAD)"
    return sha


def build_body() -> tuple[str, str]:
    fu_run = _env("FU_RUN_ID", "(missing)")
    fu_url = _env("FU_HTML_URL")
    if not fu_url and fu_run not in {"", "(missing)"}:
        fu_url = f"https://github.com/{FINDUPDATES_REPO}/actions/runs/{fu_run}"
    fu_conclusion = _env("FU_CONCLUSION", "unknown")
    fu_source = _env("FU_SOURCE", "unknown")
    orch_conclusion = _env("ORCH_CONCLUSION", "unknown")
    orch_url = _env("ORCH_HTML_URL")
    report = Path(_env("REPORT_JSON", "inputs/report.json"))
    issues_dir = Path(_env("ISSUES_OUT_DIR", "issues-out"))
    app_dir = Path(_env("DA_CHECKOUT", "workspace/DesktopApplication"))

    report_line = (
        f"`{report.as_posix()}` is present."
        if report.is_file()
        else "`inputs/report.json` is missing. Analysis used whatever files were available."
    )
    artifact_url = ""
    if fu_run not in {"", "(missing)"}:
        artifact_url = (
            f"https://github.com/{FINDUPDATES_REPO}/actions/runs/{fu_run}"
            " (download artifact `findupdates-report-json`; full JSON is not attached)"
        )

    subject_status = orch_conclusion.upper() if orch_conclusion else "UNKNOWN"
    subject = f"Orchestrator results [{subject_status}] FindUpdates run {fu_run}"

    body = "\n".join(
        [
            "FindUpdates / Orchestrator results",
            "",
            "This email is not an authorization to install, approve, or deploy.",
            "HOLD and BLOCK stay HOLD and BLOCK. GitHub Issues were not created.",
            "",
            "## FindUpdates",
            f"- Run id: `{fu_run}`",
            f"- Source: `{fu_source}`",
            f"- Conclusion: `{fu_conclusion}`",
            f"- URL: {fu_url or '(none)'}",
            f"- Report: {report_line}",
            f"- Artifact: {artifact_url or '(no FindUpdates run id)'}",
            "",
            "## Orchestrator",
            f"- Conclusion: `{orch_conclusion}`",
            f"- URL: {orch_url or '(none)'}",
            f"- DesktopApplication main SHA: `{desktop_sha(app_dir)}`",
            "",
            "## Analysis titles",
            *load_analysis_summaries(issues_dir),
            "",
        ]
    )
    return subject, body


def send_email(subject: str, body: str) -> None:
    username = _env("SMTP_USERNAME", DEFAULT_MAIL)
    password = _env("SMTP_PASSWORD")
    host = _env("SMTP_HOST", "smtp.gmail.com")
    port = int(_env("SMTP_PORT", "587") or "587")
    mail_from = _env("MAIL_FROM", DEFAULT_MAIL)
    mail_to = _env("MAIL_TO", DEFAULT_MAIL)
    _never_log_secret(password)
    if not username or not password:
        raise SystemExit(
            "SMTP_USERNAME and SMTP_PASSWORD are required. "
            "Use a Gmail App Password; do not commit it."
        )
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_from
    message["To"] = mail_to
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=60) as smtp:
        smtp.starttls(context=context)
        smtp.login(username, password)
        smtp.send_message(message)
    print(f"Sent results email to {mail_to} subject={subject}")


def main() -> int:
    subject, body = build_body()
    if _env("SMTP_DRY_RUN") == "1":
        print(subject)
        print(body)
        return 0
    send_email(subject, body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
