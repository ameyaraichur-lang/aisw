"""SBOM and licence gate: the committed SBOM matches the lockfiles and the gate really blocks."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("sbom", ROOT / "tools" / "sbom.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def comp(name: str, licence: str, scope: str = "required") -> dict[str, Any]:
    return {
        "name": name,
        "version": "1",
        "ecosystem": "pypi",
        "scope": scope,
        "licence": licence,
        "purl": f"pkg:pypi/{name}@1",
        "type": "library",
    }


def test_committed_sbom_and_report_match_the_lockfiles_and_the_gate_passes() -> None:
    sbom = _load()
    bom, report, failures = sbom.build()
    out = ROOT / "docs" / "implementation" / "sbom"
    assert failures == []
    assert (out / "aisw.cdx.json").read_text() == json.dumps(bom, indent=1, sort_keys=True) + "\n"
    assert (out / "licence-report.md").read_text() == report
    assert bom["bomFormat"] == "CycloneDX" and len(bom["components"]) > 100


def test_classification() -> None:
    c = _load().classify
    assert c(comp("a", "MIT"))[0] == "allow"
    assert c(comp("a", "Apache-2.0 OR BSD-3-Clause"))[0] == "allow"
    assert c(comp("a", "MPL-2.0"))[0] == "review"
    assert c(comp("a", "AGPL-3.0-only"))[0] == "deny"
    assert c(comp("a", "GPL-3.0-or-later"))[0] == "deny"
    assert c(comp("a", "UNKNOWN"))[0] == "deny"
    assert c(comp("a", "Some-Proprietary-1.0"))[0] == "deny"
    assert c(comp("psycopg", "LGPL-3.0-only"))[1] is not None  # accepted with a rationale
    assert c(comp("lightningcss-win32-x64-msvc", "MPL-2.0"))[1] is not None  # prefix acceptance
    assert c(comp("brand-new-copyleft", "MPL-2.0"))[1] is None


@pytest.mark.parametrize(
    "licence", ["AGPL-3.0-only", "GPL-3.0-only", "UNKNOWN", "MPL-2.0", "LGPL-3.0-only"]
)
def test_gate_fails_for_an_unaccepted_component(
    monkeypatch: pytest.MonkeyPatch, licence: str
) -> None:
    sbom = _load()
    monkeypatch.setattr(sbom, "python_components", lambda: [comp("sneaky-dep", licence)])
    monkeypatch.setattr(sbom, "npm_components", lambda: [])
    _, _, failures = sbom.build()
    assert failures and "sneaky-dep" in failures[0]


def test_gate_refuses_a_denied_licence_at_runtime_even_if_someone_accepts_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = _load()
    monkeypatch.setattr(sbom, "python_components", lambda: [comp("agpl-lib", "AGPL-3.0-only")])
    monkeypatch.setattr(sbom, "npm_components", lambda: [])
    monkeypatch.setitem(sbom.POLICY["acceptances"], "agpl-lib", "we asked nicely")
    _, _, failures = sbom.build()
    assert any("ships at runtime" in f for f in failures)
    monkeypatch.setattr(
        sbom, "python_components", lambda: [comp("agpl-lib", "AGPL-3.0-only", scope="excluded")]
    )
    assert sbom.build()[2] == []  # a dev-only tool with a recorded acceptance does not block


def test_runtime_closure_excludes_dev_tools_and_windows_only_edges() -> None:
    comps = {c["name"]: c for c in _load().python_components()}
    assert comps["fastapi"]["scope"] == "required" and comps["psycopg"]["scope"] == "required"
    assert comps["pytest"]["scope"] == "excluded" and comps["pgserver"]["scope"] == "excluded"
    assert comps["tzdata"]["scope"] == "excluded"
