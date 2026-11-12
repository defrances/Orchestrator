#!/usr/bin/env python3
"""Human review overlay is append-only and copied through Pages rebuilds."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES_SCRIPT = ROOT / "scripts" / "build-pages-site.py"
APPEND_SCRIPT = ROOT / "scripts" / "append-human-review.py"
SPEC = importlib.util.spec_from_file_location("build_pages_site", PAGES_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit(f"cannot load {PAGES_SCRIPT}")
pages = importlib.util.module_from_spec(SPEC)
sys.modules["build_pages_site"] = pages
SPEC.loader.exec_module(pages)
import github_token  # noqa: E402
import human_reviews  # noqa: E402  # loaded via scripts/ on sys.path


def _snapshot(run_id: str = "43073757791") -> dict[str, object]:
    return {
        "run_id": run_id,
        "created_at": "2026-11-12T17:00:00Z",
        "bundle": {"packages": []},
        "clusters": [],
    }


def _event(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "kb": "KB5060001",
        "config": "Config1",
        "run_id": "43073757791",
        "reviewed": True,
        "product_risk_from": "L",
        "product_risk_to": "M",
        "comment": "WPF DPI path needs lab check",
        "actor": "defrances",
        "at": "2026-11-12T17:00:00Z",
        "id": "evt1",
    }
    payload.update(overrides)
    return payload


class HumanReviewsTests(unittest.TestCase):
    def test_normalize_rejects_empty_comment(self) -> None:
        with self.assertRaisesRegex(ValueError, "comment"):
            human_reviews.normalize_event(_event(comment="  "))

    def test_normalize_rejects_bad_risk_letter(self) -> None:
        with self.assertRaisesRegex(ValueError, "product_risk_to"):
            human_reviews.normalize_event(_event(product_risk_to="HIGH"))

    def test_normalize_rejects_noop(self) -> None:
        with self.assertRaisesRegex(ValueError, "Human reviewed"):
            human_reviews.normalize_event(
                _event(reviewed=False, product_risk_from="M", product_risk_to="M")
            )

    def test_normalize_allows_unreview_of_previous(self) -> None:
        previous = human_reviews.normalize_event(_event())
        event = human_reviews.normalize_event(
            _event(
                reviewed=False,
                product_risk_from="M",
                product_risk_to="M",
                comment="Re-open until lab finishes",
                id="evt2",
            ),
            previous=previous,
        )
        self.assertFalse(event["reviewed"])
        self.assertEqual(event["product_risk_to"], "M")

    def test_na_risk_is_empty_not_invalid(self) -> None:
        event = human_reviews.normalize_event(
            _event(product_risk_from="NA", product_risk_to="H")
        )
        self.assertEqual(event["product_risk_from"], "")
        self.assertEqual(event["product_risk_to"], "H")

    def test_append_is_append_only(self) -> None:
        first = human_reviews.normalize_event(_event())
        store = human_reviews.append_event(human_reviews.empty_store(), first)
        second = human_reviews.normalize_event(_event(id="evt2", product_risk_to="C"))
        store = human_reviews.append_event(store, second)
        self.assertEqual([item["id"] for item in store["entries"]], ["evt1", "evt2"])
        latest = human_reviews.latest_for(store, "kb5060001", "Config1")
        self.assertIsNotNone(latest)
        assert latest is not None
        self.assertEqual(latest["id"], "evt2")
        self.assertEqual(latest["product_risk_to"], "C")

    def test_write_site_starts_empty_reviews_without_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "site"
            index = pages.write_site(out, [_snapshot()], repo="defrances/Orchestrator")
            self.assertEqual(index["repo"], "defrances/Orchestrator")
            store = json.loads((out / "data" / "reviews.json").read_text(encoding="utf-8"))
            self.assertEqual(store, {"entries": []})
            js = (out / "assets" / "reviews.js").read_text(encoding="utf-8")
            self.assertTrue(js.startswith("window.SITE_REVIEWS = "))
            html = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn("assets/reviews.js", html)
            self.assertNotIn("Alcon", html)

    def test_write_site_copies_reviews_from_history(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history = Path(raw) / "site-prev"
            out = Path(raw) / "site"
            event = human_reviews.normalize_event(_event())
            human_reviews.write_store(
                history,
                human_reviews.append_event(human_reviews.empty_store(), event),
            )
            pages.write_site(out, [_snapshot("99")], history_dir=history)
            copied = json.loads((out / "data" / "reviews.json").read_text(encoding="utf-8"))
            self.assertEqual(len(copied["entries"]), 1)
            self.assertEqual(copied["entries"][0]["kb"], "KB5060001")
            self.assertEqual(copied["entries"][0]["comment"], event["comment"])
            js = (out / "assets" / "reviews.js").read_text(encoding="utf-8")
            self.assertIn("KB5060001", js)
            rebuilt = Path(raw) / "site2"
            pages.write_site(rebuilt, [_snapshot("100")], history_dir=out)
            again = json.loads((rebuilt / "data" / "reviews.json").read_text(encoding="utf-8"))
            self.assertEqual(again["entries"][0]["id"], event["id"])

    def test_append_cli_records_and_rejects_without_rewriting(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            site = Path(raw) / "gh-pages"
            payload = Path(raw) / "ok.json"
            payload.write_text(json.dumps(_event()) + "\n", encoding="utf-8")
            ok = subprocess.run(
                [sys.executable, str(APPEND_SCRIPT), "--site", str(site), "--payload-file", str(payload)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("KB5060001", ok.stdout)
            self.assertNotIn("ghp_", ok.stdout)
            store = json.loads((site / "data" / "reviews.json").read_text(encoding="utf-8"))
            self.assertEqual(len(store["entries"]), 1)
            bad = Path(raw) / "bad.json"
            bad.write_text(json.dumps(_event(comment="")) + "\n", encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, str(APPEND_SCRIPT), "--site", str(site), "--payload-file", str(bad)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(failed.returncode, 1)
            self.assertIn("comment", failed.stderr)
            after = json.loads((site / "data" / "reviews.json").read_text(encoding="utf-8"))
            self.assertEqual(len(after["entries"]), 1)

    def test_github_token_reads_secrets_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            github_token.write("gho_test_not_real", root=root)
            saved = {
                name: os.environ.pop(name, None)
                for name in ("GITHUB_TOKEN", "GH_TOKEN", "ORCHESTRATOR_PAT")
            }
            try:
                self.assertEqual(github_token.load(root), "gho_test_not_real")
            finally:
                for name, value in saved.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value

    def test_github_token_load_prefers_os_store_without_root(self) -> None:
        original_os_read = github_token._os_read
        saved = {
            name: os.environ.pop(name, None)
            for name in ("GITHUB_TOKEN", "GH_TOKEN", "ORCHESTRATOR_PAT")
        }
        github_token._os_read = lambda: "gho_from_vault"  # type: ignore[method-assign]
        try:
            self.assertEqual(github_token.load(), "gho_from_vault")
        finally:
            github_token._os_read = original_os_read  # type: ignore[method-assign]
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_github_token_write_with_root_skips_os_store(self) -> None:
        original_os_write = github_token._os_write
        called = {"n": 0}

        def boom(token: str) -> bool:
            called["n"] += 1
            raise AssertionError("os store must not run for a test root")

        github_token._os_write = boom  # type: ignore[method-assign]
        try:
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                github_token.write("gho_test_not_real", root=root)
                self.assertEqual(github_token.load(root), "gho_test_not_real")
            self.assertEqual(called["n"], 0)
        finally:
            github_token._os_write = original_os_write  # type: ignore[method-assign]

    def test_store_github_token_script_stdin_to_root(self) -> None:
        script = ROOT / "scripts" / "store-github-token.py"
        saved = {
            name: os.environ.pop(name, None)
            for name in ("GITHUB_TOKEN", "GH_TOKEN", "ORCHESTRATOR_PAT")
        }
        try:
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                done = subprocess.run(
                    [sys.executable, str(script), "--root", str(root), "--stdin"],
                    input="gho_test_not_real\n",
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertNotIn("gho_test_not_real", done.stdout)
                self.assertNotIn("gho_test_not_real", done.stderr)
                self.assertEqual(github_token.load(root), "gho_test_not_real")
                again = subprocess.run(
                    [sys.executable, str(script), "--root", str(root)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertIn("already stored", again.stdout)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_windows_credential_roundtrip_throwaway_target(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows Credential Manager")
        target = "defrances/Orchestrator/review-pat-test"
        try:
            self.assertTrue(
                github_token._windows_cred_write(target, "github-pat", "gho_test_not_real")
            )
            self.assertEqual(github_token._windows_cred_read(target), "gho_test_not_real")
        finally:
            github_token._windows_cred_delete(target)

    def test_write_site_does_not_publish_token_json(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            history = Path(raw) / "site-prev"
            (history / "data").mkdir(parents=True)
            (history / "data" / "github.json").write_text(
                '{"token": "gho_must_not_publish"}\n', encoding="utf-8"
            )
            github_token.write("gho_must_not_publish", root=history)
            out = Path(raw) / "site"
            pages.write_site(out, [_snapshot("101")], history_dir=history)
            self.assertFalse((out / "data" / "github.json").exists())
            self.assertFalse((out / ".secrets" / "github.json").exists())
            published = "\n".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in out.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("gho_must_not_publish", published)


if __name__ == "__main__":
    unittest.main()
