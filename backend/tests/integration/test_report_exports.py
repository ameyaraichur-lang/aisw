"""PDF and DOCX report exports through the API, and the frozen control-gap matrix (ADR-038)."""

from __future__ import annotations

import io
import zipfile
from typing import Any

from aisw.reporting.export import DRAFT, MEDIA
from tests.slice import Slice
from tests.unit.test_report_exports import _pdf_text

EXPECTED = ["host-1", "host-2", "host-3"]


def report(sl: Slice) -> tuple[str, dict[str, Any]]:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    [first, *_] = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()
    body = sl.call("GET", f"/api/v1/reports/{first['report_id']}", "carol").json()
    return first["report_id"], body


def test_the_gap_matrix_is_frozen_into_the_hashed_report(sl: Slice) -> None:
    rid, body = report(sl)
    gaps = body["control_gaps"]
    assert gaps["catalog_version"] == "1.0.0" and gaps["frameworks"]
    outcomes = {c["control_id"]: c["outcome"] for c in body["controls"]}
    rows = [r for fw in gaps["frameworks"] for r in fw["rows"]]
    assert rows and all(r["mapping"] == "PROPOSED" for r in rows)
    for r in rows:
        assert all(p["outcome"] == outcomes.get(p["control_id"], "NOT_ASSESSED")
                   for p in r["pack_controls"])  # fmt: skip
    html = sl.call("GET", f"/api/v1/reports/{rid}?format=html", "carol").text
    assert "Control-gap matrix" in html and "Architecture delta" in html

    key = next(
        f"{p['control_id']}|{fw['framework']}|{r['control_id']}"
        for fw in gaps["frameworks"] for r in fw["rows"] for p in r["pack_controls"]
        if len(r["pack_controls"]) == 1
    )  # fmt: skip
    ok = sl.call("POST", "/api/v1/framework-mappings/reviews", "paula",
                 json={"key": key, "decision": "APPROVED", "reason": "matches our control set"})  # fmt: skip
    assert ok.status_code == 200, ok.text
    again = sl.call("GET", f"/api/v1/reports/{rid}", "carol").json()
    assert again["control_gaps"] == gaps  # the stored report does not change afterwards
    _, newer = report(sl)
    pack_control, framework, control = key.split("|")
    [row] = [r for fw in newer["control_gaps"]["frameworks"] if fw["framework"] == framework
             for r in fw["rows"] if r["control_id"] == control]  # fmt: skip
    assert row["mapping"] == "APPROVED"


def test_pdf_and_docx_exports_follow_the_report_download_rules(sl: Slice) -> None:
    rid, body = report(sl)
    pdf = sl.call("GET", f"/api/v1/reports/{rid}?format=pdf", "carol")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == MEDIA["pdf"]
    assert pdf.headers["x-report-hash"] and pdf.content.startswith(b"%PDF-1.4")
    text = _pdf_text(pdf.content)
    assert DRAFT in text and "Exported by carol" in text and body["run_id"] in text

    denied = sl.call("GET", f"/api/v1/reports/{rid}?format=docx&download=1", "carol")
    assert denied.status_code == 403  # a draft is downloaded only by someone who can approve it
    docx = sl.call("GET", f"/api/v1/reports/{rid}?format=docx&download=1", "rita")
    assert docx.status_code == 200 and docx.headers["content-type"] == MEDIA["docx"]
    assert docx.headers["content-disposition"] == f'attachment; filename="{rid}.docx"'
    doc = zipfile.ZipFile(io.BytesIO(docx.content)).read("word/document.xml").decode()
    assert "Exported by rita" in doc and "Control-gap matrix" in doc

    assert sl.call("GET", f"/api/v1/reports/{rid}?format=pdf", "dave").status_code in {403, 404}
    assert sl.call("GET", f"/api/v1/reports/{rid}?format=rtf", "carol").status_code == 422
    audit = sl.sql("SELECT actor, action, result FROM audit_events WHERE resource=:r ORDER BY seq",
                   r=f"report:{rid}")  # fmt: skip
    assert [tuple(a) for a in audit][-3:] == [
        ("carol", "report.view", "SUCCESS"),
        ("carol", "report.export", "DENIED"),
        ("rita", "report.export", "SUCCESS"),
    ]
