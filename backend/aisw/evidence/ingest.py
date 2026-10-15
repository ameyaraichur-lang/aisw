"""Evidence ingest: validate -> redact -> canonicalise -> hash -> store (+ metadata row).

Every external tool output is untrusted data. Secrets are redacted BEFORE anything is stored or
hashed, so neither the evidence file, the database nor any later prompt can contain them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aisw.contracts.base import canonical_json
from aisw.contracts.domain import EvidenceArtifact
from aisw.core.redaction import redact_obj
from aisw.evidence.store import EvidenceStore

MAX_BYTES = 5_000_000
ALLOWED_MEDIA = {"application/json"}


class IngestRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PreparedEvidence:
    data: bytes
    redacted: bool
    media_type: str = "application/json"


def prepare(raw: Any, *, media_type: str = "application/json") -> PreparedEvidence:
    if media_type not in ALLOWED_MEDIA:
        raise IngestRejected("MEDIA_TYPE_NOT_ALLOWED")
    cleaned = redact_obj(raw)
    try:
        data = canonical_json(cleaned)
    except (TypeError, ValueError) as exc:
        raise IngestRejected("NOT_SERIALISABLE") from exc
    if len(data) > MAX_BYTES:
        raise IngestRejected("TOO_LARGE")
    return PreparedEvidence(data, redacted=cleaned != raw, media_type=media_type)


def evidence_ref(tenant: str, project: str, run: str, adapter: str, task: str, name: str) -> str:
    return f"evidence://{tenant}/{project}/{run}/{adapter}/{task}/{name}"


def store_evidence(
    conn: Connection,
    store: EvidenceStore,
    prepared: PreparedEvidence,
    *,
    tenant_id: str,
    project_id: str,
    run_id: str,
    task_id: str,
    ref: str,
    source: str,
    tool_version: str,
    collected_at: datetime,
) -> EvidenceArtifact:
    content_hash = store.put(tenant_id, prepared.data)
    conn.execute(
        text(
            "INSERT INTO evidence_artifacts (tenant_id, evidence_ref, project_id, run_id, task_id, "
            "content_hash, size_bytes, media_type, source, tool_version, collected_at, redacted) "
            "VALUES (:t, :ref, :p, :r, :task, :h, :n, :m, :s, :v, :c, :red) "
            "ON CONFLICT (tenant_id, evidence_ref) DO NOTHING"
        ),
        {
            "t": tenant_id, "ref": ref, "p": project_id, "r": run_id, "task": task_id,
            "h": content_hash, "n": len(prepared.data), "m": prepared.media_type, "s": source,
            "v": tool_version, "c": collected_at, "red": prepared.redacted,
        },
    )  # fmt: skip
    return EvidenceArtifact(
        evidence_ref=ref, tenant_id=tenant_id, project_id=project_id, run_id=run_id,
        content_hash=content_hash, size_bytes=len(prepared.data), media_type=prepared.media_type,
        source=source, tool_version=tool_version, collected_at=collected_at,
        redacted=prepared.redacted,
    )  # fmt: skip
