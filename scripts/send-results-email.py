#!/usr/bin/env python3
"""Email one Orchestrator cluster per message in GitHub Issue format. Never logs the password."""

from __future__ import annotations

import html
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

DEFAULT_MAIL = "andrey02061987@gmail.com"
FINDUPDATES_REPO = os.environ.get("FINDUPDATES_REPO", "defrances/FindUpdates")
NO_CLUSTER_SUBJECT = "Orchestrator: no vendor-update clusters"
NO_CLUSTER_BODY = (
    "No vendor-update clusters were written for this run.\n\n"
    "This email is not an authorization to install, approve, or deploy. "
    "HOLD and BLOCK stay HOLD and BLOCK. GitHub Issues were not created."
)


@dataclass(frozen=True)
class Mail:
    subject: str
    plain: str
    html: str


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _never_log_secret(value: str) -> None:
    del value


def desktop_sha(app_dir: Path) -> str:
    if not (app_dir / ".git").exists():
        return "(DesktopApplication checkout not available)"
    result = subprocess.run(
        ["git", "-C", str(app_dir), "rev-parse", "HEAD"],
        check=False,
        text=True,
        capture_output=True,
    )
    sha = (result.stdout or "").strip()
    if result.returncode != 0 or not sha:
        return "(unable to read DesktopApplication HEAD)"
    return sha


def load_issue_payloads(directory: Path) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    if not directory.is_dir():
        return payloads
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"{path.name}: invalid JSON ({exc})", file=sys.stderr)
            continue
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
                print(f"{path.name}: refused (token field)", file=sys.stderr)
                continue
            title = str(item.get("title") or "").strip()
            body = str(item.get("body") or "").strip()
            if not title or not body:
                continue
            payloads.append(item)
    return payloads


def run_footer(app_dir: Path | None = None) -> str:
    fu_run = _env("FU_RUN_ID", "(missing)")
    fu_url = _env("FU_HTML_URL")
    if not fu_url and fu_run not in {"", "(missing)"}:
        fu_url = f"https://github.com/{FINDUPDATES_REPO}/actions/runs/{fu_run}"
    orch_url = _env("ORCH_HTML_URL") or "(none)"
    sha = desktop_sha(app_dir or Path(_env("DA_CHECKOUT", "workspace/DesktopApplication")))
    return "\n".join(
        [
            f"DesktopApplication `main`: `{sha}`",
            "",
            f"- FindUpdates: {fu_url or '(none)'}",
            f"- Orchestrator: {orch_url}",
            "- Windows patch bundle artifact: `windows-patch-bundle` (KB manifest + APPLY.ps1, not .msu files)",
            "",
            "This email is not an authorization to install, approve, or deploy.",
            "HOLD and BLOCK stay HOLD and BLOCK. GitHub Issues were not created.",
        ]
    )


def attach_footer(body: str, footer: str) -> str:
    return body.rstrip() + "\n\n---\n\n" + footer.strip() + "\n"


_HTTPS_LINK = re.compile(r"\[([^\]]+)\]\((https://[^)\s]+)\)")


def _inline_no_links(text: str) -> str:
    parts = re.split(r"(`[^`]+`)", text)
    rendered: list[str] = []
    for part in parts:
        if len(part) >= 2 and part.startswith("`") and part.endswith("`"):
            rendered.append(f"<code>{html.escape(part[1:-1])}</code>")
            continue
        escaped = html.escape(part)
        escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
        rendered.append(escaped)
    return "".join(rendered)


def _inline(text: str) -> str:
    pieces: list[str] = []
    pos = 0
    for match in _HTTPS_LINK.finditer(text):
        pieces.append(_inline_no_links(text[pos : match.start()]))
        href = html.escape(match.group(2), quote=True)
        pieces.append(f'<a href="{href}">{_inline_no_links(match.group(1))}</a>')
        pos = match.end()
    pieces.append(_inline_no_links(text[pos:]))
    return "".join(pieces)


def _is_table_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _split_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _heading_level(line: str) -> int | None:
    match = re.match(r"^(#{1,6})\s+(.+)$", line)
    if not match:
        return None
    return len(match.group(1))


def markdown_to_html(markdown: str) -> str:
    without_comments = re.sub(r"<!--.*?-->", "", markdown, flags=re.DOTALL)
    lines = without_comments.replace("\r\n", "\n").split("\n")
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("```"):
            fence = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                fence.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            code = html.escape("\n".join(fence))
            blocks.append(f"<pre><code>{code}</code></pre>")
            continue
        if stripped in {"---", "***", "___"}:
            blocks.append("<hr>")
            index += 1
            continue
        heading = _heading_level(stripped)
        if heading is not None:
            title = re.sub(r"^#{1,6}\s+", "", stripped)
            blocks.append(f"<h{heading}>{_inline(title)}</h{heading}>")
            index += 1
            continue
        if stripped.startswith("|") and index + 1 < len(lines) and _is_table_separator(
            lines[index + 1]
        ):
            headers = _split_table_row(stripped)
            index += 2
            rows: list[list[str]] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                if not _is_table_separator(lines[index]):
                    rows.append(_split_table_row(lines[index]))
                index += 1
            head = "".join(f"<th>{_inline(cell)}</th>" for cell in headers)
            body_rows = []
            for row in rows:
                padded = row + [""] * max(0, len(headers) - len(row))
                body_rows.append(
                    "<tr>"
                    + "".join(f"<td>{_inline(cell)}</td>" for cell in padded[: len(headers)])
                    + "</tr>"
                )
            blocks.append(
                "<table><thead><tr>"
                + head
                + "</tr></thead><tbody>"
                + "".join(body_rows)
                + "</tbody></table>"
            )
            continue
        if stripped.startswith(("- ", "* ")):
            items = []
            while index < len(lines) and lines[index].strip().startswith(("- ", "* ")):
                items.append(f"<li>{_inline(lines[index].strip()[2:])}</li>")
                index += 1
            blocks.append("<ul>" + "".join(items) + "</ul>")
            continue
        paragraph = [stripped]
        index += 1
        while index < len(lines):
            nxt = lines[index].strip()
            if (
                not nxt
                or nxt.startswith("|")
                or nxt.startswith("```")
                or nxt.startswith(("- ", "* "))
                or nxt in {"---", "***", "___"}
                or _heading_level(nxt) is not None
            ):
                break
            paragraph.append(nxt)
            index += 1
        blocks.append(f"<p>{_inline(' '.join(paragraph))}</p>")
    inner = "\n".join(blocks)
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;"
        "line-height:1.45;color:#1f2328;}"
        "table{border-collapse:collapse;margin:12px 0;}"
        "th,td{border:1px solid #d0d7de;padding:6px 10px;text-align:left;vertical-align:top;}"
        "th{background:#f6f8fa;}"
        "code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;"
        "background:#f6f8fa;padding:0 4px;}"
        "pre{background:#f6f8fa;padding:12px;overflow:auto;}"
        "pre code{background:none;padding:0;}"
        "h2{border-bottom:1px solid #d0d7de;padding-bottom:0.3em;}"
        "hr{border:none;border-top:1px solid #d0d7de;}"
        "a{color:#0969da;}"
        "</style></head><body>"
        f"{inner}"
        "</body></html>"
    )


def build_mail(subject: str, body: str, footer: str) -> Mail:
    plain = attach_footer(body, footer)
    return Mail(subject=subject, plain=plain, html=markdown_to_html(plain))


def build_messages(
    issues_dir: Path | None = None,
    app_dir: Path | None = None,
) -> list[Mail]:
    directory = issues_dir or Path(_env("ISSUES_OUT_DIR", "issues-out"))
    footer = run_footer(app_dir)
    payloads = load_issue_payloads(directory)
    if not payloads:
        return [build_mail(NO_CLUSTER_SUBJECT, NO_CLUSTER_BODY, footer)]
    messages: list[Mail] = []
    for item in payloads:
        title = str(item.get("title") or "").strip()
        body = str(item.get("body") or "").strip()
        messages.append(build_mail(title, body, footer))
    return messages


def send_mail(mail: Mail) -> None:
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
    message["Subject"] = mail.subject
    message["From"] = mail_from
    message["To"] = mail_to
    message.set_content(mail.plain)
    message.add_alternative(mail.html, subtype="html")
    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=60) as smtp:
        smtp.starttls(context=context)
        smtp.login(username, password)
        smtp.send_message(message)
    print(f"Sent results email to {mail_to} subject={mail.subject}")


def main() -> int:
    messages = build_messages()
    if _env("SMTP_DRY_RUN") == "1":
        for mail in messages:
            print(f"SUBJECT: {mail.subject}")
            print(mail.plain)
            print("---html---")
            print(mail.html)
            print("========")
        print(f"sent={len(messages)} failed=0")
        return 0
    sent = 0
    failed = 0
    for mail in messages:
        try:
            send_mail(mail)
            sent += 1
        except SystemExit as exc:
            print(exc, file=sys.stderr)
            failed += 1
            break
        except Exception as exc:
            print(f"failed subject={mail.subject}: {exc}", file=sys.stderr)
            failed += 1
    print(f"sent={sent} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
