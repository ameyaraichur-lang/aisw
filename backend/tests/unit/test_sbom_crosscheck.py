"""The lockfile SBOM is cross-checked against Syft components and ScanCode licence findings."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("sbom_crosscheck", ROOT / "tools" / "sbom_crosscheck.py")  # fmt: skip
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


X = _load()
SBOM = {
    "components": [
        {"name": "Typing_Extensions", "version": "4.0.0", "purl": "pkg:pypi/typing-extensions@4.0.0", "scope": "required"},
        {"name": "psycopg", "version": "3.2.0", "purl": "pkg:pypi/psycopg@3.2.0", "scope": "required"},
        {"name": "@tanstack/react-query", "version": "5.0.0", "purl": "pkg:npm/%40tanstack/react-query@5.0.0", "scope": "required"},
        {"name": "vitest", "version": "3.0.0", "purl": "pkg:npm/vitest@3.0.0", "scope": "excluded"},
    ]
}  # fmt: skip


def syft(*comps: tuple[str, str, str], extra: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "components": [{"name": n, "version": v, "purl": f"pkg:{e}/{n}@{v}", "type": "library"} for e, n, v in comps]
        + (extra or [])
    }  # fmt: skip


def test_every_runtime_component_must_be_found_at_its_version() -> None:
    ok = syft(("pypi", "typing-extensions", "4.0.0"), ("pypi", "psycopg", "3.2.0"),
              ("npm", "@tanstack/react-query", "5.0.0"),
              extra=[{"name": "libssl3", "version": "3.0.13", "purl": "pkg:deb/ubuntu/libssl3@3.0.13", "type": "library"},
                     {"name": "x.py", "type": "file"}])  # fmt: skip
    failures, report = X.check(SBOM, [ok], None)
    assert failures == []
    assert "- pypi: 2 of 2 runtime components confirmed by Syft" in report
    assert any("found only by Syft (deb, 1): libssl3 3.0.13" in r for r in report)
    assert "- licences: ScanCode not run in this job" in report

    drift = syft(("pypi", "typing-extensions", "4.1.0"), ("npm", "@tanstack/react-query", "5.0.0"))
    failures, _ = X.check(SBOM, [drift], None)
    assert failures == [
        "pypi: runtime component psycopg@3.2.0 not found by Syft",
        "pypi: runtime component typing-extensions@4.0.0 at another version (Syft: 4.1.0)",
    ]


def test_an_ecosystem_syft_did_not_see_is_reported_and_nothing_seen_fails() -> None:
    _, report = X.check(SBOM, [syft(("pypi", "typing-extensions", "4.0.0"), ("pypi", "psycopg", "3.2.0"))], None)  # fmt: skip
    assert "- npm: NOT CHECKED (no npm components in the Syft input)" in report
    failures, _ = X.check(SBOM, [syft()], None)
    assert any("no ecosystem could be checked" in f for f in failures)
    failures, _ = X.check(SBOM, None, None)
    assert failures == ["nothing to check: pass Syft and/or ScanCode output"]


def scan(path: str, expr: str | None, detections: list[str] = ()) -> dict[str, Any]:  # type: ignore[assignment]
    return {"path": path, "detected_license_expression_spdx": expr,
            "license_detections": [{"license_expression_spdx": d} for d in detections]}  # fmt: skip


def test_scancode_denied_licences_fail_unless_accepted() -> None:
    doc = {"files": [
        scan("licences/pypi/typing-extensions@4.0.0/LICENSE", "PSF-2.0"),
        scan("licences/pypi/psycopg@3.2.0/LICENSE.txt", "LGPL-3.0-only"),
        scan("licences/npm/@tanstack__react-query@5.0.0/LICENSE", None, ["MIT AND (GPL-3.0-only OR MIT)"]),
    ]}  # fmt: skip
    failures, report = X.check(SBOM, None, doc)
    assert failures == ["npm: ScanCode found GPL-3.0-only in @tanstack/react-query@5.0.0"]
    assert any("ScanCode read 3 of 3" in r for r in report)

    accepted = {"files": [scan("licences/pypi/psycopg@3.2.0/LICENSE.txt", "GPL-3.0-only")]}
    failures, report = X.check(SBOM, None, accepted)
    assert failures == []  # psycopg has a recorded acceptance in the licence policy
    assert any("no licence text detected in: @tanstack/react-query@5.0.0, typing-extensions@4.0.0" in r for r in report)  # fmt: skip


def test_the_cli_appends_a_summary_and_fails_on_findings(tmp_path: Path) -> None:
    good = tmp_path / "s.json"
    good.write_text(json.dumps(syft()))
    summary = tmp_path / "summary.md"
    assert X.main(["check", "--syft", str(good), "--summary", str(summary)]) == 1
    assert "FAIL: no ecosystem could be checked" in summary.read_text()
