"""Control-gap matrix, architecture delta, and the PDF and DOCX writers (ADR-038)."""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from aisw.policy.engine import PackRegistry
from aisw.policy.mappings import builtin as builtin_mappings
from aisw.reporting.export import DRAFT, export, stamp_lines
from aisw.reporting.gaps import _state, architecture_delta, control_gaps

HOSTILE = 'Weak (cipher) \\ <script>alert("x")</script> & \x07bell \u2603 \U0001f600'


def body(**over: Any) -> dict[str, Any]:
    b: dict[str, Any] = {
        "title": "AISW assessment report", "run_id": "run-1", "scope_manifest_hash": "a" * 64,
        "policy_versions": ["config-baseline:1.0.0"], "generated_at": "2026-10-16T10:00:00+00:00",
        "banner": None, "notice": None, "disclaimer": "Not a certification.",
        "finding_counts": {"total": 1, "HIGH": 1},
        "findings": [{"finding_id": "f-1", "severity": "HIGH", "title": HOSTILE,
                      "affected_assets": ["host-1"], "evidence_refs": ["ev-1"],
                      "risk": {"tier": None, "provisional_tier": "P1", "rubric_version": "1.0.0"}}],
        "coverage": [{"segment": "hosts", "expected_count": 3, "reconciled_count": 2,
                      "unknown_count": 1, "unsupported_count": 0, "reasons": ["host-3 unreachable"]}],
        "limitations": ["Segment hosts: coverage incomplete."],
        "evidence_manifest": [{"ref": "ev-1", "hash": "b" * 64}],
        "scenarios": [], "pending_review": [],
        "recommendations": [{"recommendation_id": "r-1", "title": "Harden SSH", "action": "Apply",
                             "catalog_ref": "AC-HOST-01@1.0.0", "target_pattern": "Baseline host",
                             "finding_refs": ["f-1"], "affected_assets": ["host-1"],
                             "risk_tier": None, "owner_questions": ["Who owns host-1?"],
                             "rollback": "Restore config", "acceptance_test": "Re-run"}],
        "control_gaps": {"catalog_version": "1.0.0", "notice": "Proposed mappings.", "frameworks": [
            {"framework": "NIST-CSF", "version": "2.0", "name": "NIST CSF",
             "summary": {"GAP": 1, "EXCEPTION": 0, "UNKNOWN": 0, "NO_GAP_OBSERVED": 0,
                         "NOT_APPLICABLE": 0},
             "rows": [{"control_id": "PR.IR-01", "title": "Networks are protected", "state": "GAP",
                       "pack_controls": [{"control_id": "CB-NET-1", "outcome": "FAIL"}],
                       "mapping": "PROPOSED"}]}]},
    }  # fmt: skip
    return {**b, **over}


STAMP = stamp_lines("bob", "tenant-a", "2026-10-16T11:00:00+00:00", "PENDING", "c" * 64)


def test_gap_state_never_claims_compliance_and_unassessed_is_unknown() -> None:
    assert _state(["PASS", "FAIL"]) == "GAP"
    assert _state(["PASS", "EXCEPTION"]) == "EXCEPTION"
    assert _state(["PASS", "NOT_ASSESSED"]) == "UNKNOWN" and _state(["ERROR"]) == "UNKNOWN"
    assert _state(["NOT_APPLICABLE"]) == "NOT_APPLICABLE"
    assert _state(["PASS", "NOT_APPLICABLE"]) == "NO_GAP_OBSERVED"


def test_control_gaps_follow_reviewed_mappings_and_ignore_rejected_ones() -> None:
    pack = PackRegistry.builtin().get("config-baseline:1.0.0")
    assert pack is not None
    catalog = builtin_mappings()
    some = sorted(pack.control_ids())[0]
    outcomes = {c: "PASS" for c in pack.control_ids()} | {some: "FAIL"}
    keys = [m.key for m in catalog.for_control(some)]
    g = control_gaps(pack, outcomes, catalog, {})
    rows = [(fw["framework"], r) for fw in g["frameworks"] for r in fw["rows"]]
    hit = [r for _, r in rows if any(p["control_id"] == some for p in r["pack_controls"])]
    assert hit and all(r["state"] == "GAP" and r["mapping"] == "PROPOSED" for r in hit)
    assert g["notice"] == catalog.notice
    approved = control_gaps(pack, outcomes, catalog, dict.fromkeys(keys, "APPROVED"))
    assert {r["mapping"] for fw in approved["frameworks"] for r in fw["rows"]
            if [p["control_id"] for p in r["pack_controls"]] == [some]} == {"APPROVED"}  # fmt: skip
    rejected = control_gaps(pack, outcomes, catalog, dict.fromkeys(keys, "REJECTED"))
    assert not [r for fw in rejected["frameworks"] for r in fw["rows"]
                if any(p["control_id"] == some for p in r["pack_controls"])]  # fmt: skip
    missing = control_gaps(pack, {}, catalog, {})  # nothing assessed: unknown, never a pass
    assert {r["state"] for fw in missing["frameworks"] for r in fw["rows"]} == {"UNKNOWN"}


def test_architecture_delta_puts_findings_beside_the_target() -> None:
    [row] = architecture_delta(body())
    assert row["current"] == [HOSTILE] and row["target"] == "Baseline host"
    assert row["tier"] is None and row["pattern"] == "AC-HOST-01@1.0.0"


def _pdf_text(pdf: bytes) -> str:
    out = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", pdf, re.S):
        out.append(zlib.decompress(m.group(1)).decode("latin-1"))
    return "\n".join(out)


def test_pdf_is_well_formed_deterministic_and_escapes_text() -> None:
    a = export(body(), "pdf", STAMP, approved=False)
    assert a == export(body(), "pdf", STAMP, approved=False)
    assert a.startswith(b"%PDF-1.4") and a.rstrip().endswith(b"%%EOF")
    start = int(a.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    assert a[start:].startswith(b"xref")
    count = int(a[start:].split(b"\n")[1].split()[1])
    offsets = [int(x[:10]) for x in a[start:].split(b"\n")[3 : 2 + count]]
    for n, off in enumerate(offsets, start=1):
        assert a[off:].startswith(b"%d 0 obj" % n)
    pages = int(re.search(rb"/Type /Pages /Count (\d+)", a).group(1))  # type: ignore[union-attr]
    assert pages >= 1 and len(re.findall(rb"/Type /Page ", a)) == pages
    text = _pdf_text(a)
    assert DRAFT in text and "Control-gap matrix" in text and "Architecture delta" in text
    assert "Weak \\(cipher\\) \\\\ <script>" in text  # escaped PDF literal, control char dropped
    assert "\x07" not in text and "?" in text  # outside Windows-1252 prints as "?"
    assert f"page 1 of {pages}" in text
    approved = export(body(), "pdf", STAMP[1:], approved=True)
    assert DRAFT not in _pdf_text(approved)


def test_long_tables_break_across_pages_and_repeat_the_header() -> None:
    many = [{"ref": f"ev-{i:03d}", "hash": f"{i:064x}"} for i in range(200)]
    pdf = export(body(evidence_manifest=many), "pdf", STAMP, approved=False)
    text = _pdf_text(pdf)
    pages = int(re.search(rb"/Count (\d+)", pdf).group(1))  # type: ignore[union-attr]
    assert pages >= 4 and text.count("(SHA-256) Tj") >= pages - 2
    assert "ev-199" in text


def test_docx_is_a_valid_package_deterministic_and_escapes_text() -> None:
    a = export(body(), "docx", STAMP, approved=False)
    assert a == export(body(), "docx", STAMP, approved=False)
    z = zipfile.ZipFile(io.BytesIO(a))
    names = z.namelist()
    assert names[0] == "[Content_Types].xml" and "word/header1.xml" in names
    for n in names:
        ET.fromstring(z.read(n))  # noqa: S314 - our own output; checks it is well-formed
    types = z.read("[Content_Types].xml").decode()
    for part in ("/word/document.xml", "/word/styles.xml", "/word/header1.xml"):
        assert f'PartName="{part}"' in types
    rels = z.read("word/_rels/document.xml.rels").decode()
    for target in re.findall(r'Target="([^"]+)"', rels):
        assert f"word/{target}" in names
    doc = z.read("word/document.xml").decode()
    assert "&lt;script&gt;" in doc and "<script>" not in doc and "\x07" not in doc
    assert "\u2603" in doc and "Control-gap matrix" in doc and "<w:tblHeader/>" in doc
    assert DRAFT in z.read("word/header1.xml").decode()
    assert {i.date_time for i in z.infolist()} == {(1980, 1, 1, 0, 0, 0)}
    approved = zipfile.ZipFile(io.BytesIO(export(body(), "docx", STAMP[1:], approved=True)))
    assert "word/header1.xml" not in approved.namelist()


@pytest.mark.parametrize("fmt", ["pdf", "docx"])
def test_a_report_from_before_the_matrix_still_exports(fmt: str) -> None:
    old = body()
    del old["control_gaps"]
    out = export(old | {"recommendations": [], "evidence_manifest": []}, fmt, STAMP, approved=False)  # type: ignore[arg-type]
    assert len(out) > 500
