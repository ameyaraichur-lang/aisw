"""PDF and DOCX exports of a stored report body (ADR-038)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from aisw.reporting.document import report_blocks
from aisw.reporting.docx import render_docx
from aisw.reporting.pdf import render_pdf

Format = Literal["pdf", "docx"]
MEDIA = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
DRAFT = "DRAFT: this report has not been approved and must not be distributed."


def stamp_lines(actor: str, tenant: str, when: str, approval: str, report_hash: str) -> list[str]:
    head = [] if approval == "APPROVED" else [DRAFT]
    return [*head, f"Exported by {actor} ({tenant}) at {when}. Approval state: {approval}. "
                   f"Report hash {report_hash}."]  # fmt: skip


def export(body: dict[str, Any], fmt: Format, stamp: list[str], *, approved: bool) -> bytes:
    blocks = report_blocks(body, stamp)
    created = datetime.fromisoformat(body["generated_at"])
    title = f"{body['title']} - run {body['run_id']}"
    header = None if approved else DRAFT
    render = render_pdf if fmt == "pdf" else render_docx
    return render(blocks, title=title, created=created, header=header)
