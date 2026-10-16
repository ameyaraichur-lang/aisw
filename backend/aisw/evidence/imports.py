"""Uploaded import files: the ONLY way import adapters receive data.

Adapters never see a path, URL or tenant-controlled identifier other than an opaque ``import_id``.
Uploads are size-bounded, must be UTF-8 text, are redacted before they are hashed or stored, and are
re-verified (hash, tenant, project, kind) on every read. Reading is tenant-scoped by RLS.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Engine, text

from aisw.core.db import tenant_connection
from aisw.core.redaction import redact_text
from aisw.evidence.store import EvidenceIntegrityError, EvidenceStore

MAX_IMPORT_BYTES = 5_000_000
IMPORT_KINDS = frozenset(
    {"cmdb_csv", "cmdb_json", "prowler_json", "greenbone_xml", "openscap_xccdf", "wazuh_json",
     "nmap_xml", "zap_json", "aws_security_groups_json", "iptables_save", "kubescape_json",
     "k8s_rbac_json", "ad_users_csv", "ldif", "aws_credential_report_csv", "netbox_json",
     "servicenow_json", "nessus_xml", "tenable_json", "qualys_xml", "trivy_json"}
)  # fmt: skip
_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


class ImportRejected(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ImportMeta:
    import_id: str
    kind: str
    filename: str
    content_hash: str
    size_bytes: int
    redacted: bool


def safe_filename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]  # never keep a client-supplied path
    return _FILENAME.sub("_", base)[:100].lstrip(".") or "upload"


class ImportStore:
    def __init__(self, engine: Engine, evidence: EvidenceStore) -> None:
        self.engine, self.evidence = engine, evidence

    def upload(
        self, *, tenant_id: str, project_id: str, actor: str, kind: str, filename: str,
        content: str, now: datetime,
    ) -> ImportMeta:  # fmt: skip
        if kind not in IMPORT_KINDS:
            raise ImportRejected("UNKNOWN_IMPORT_KIND")
        if "\x00" in content:
            raise ImportRejected("BINARY_CONTENT")
        cleaned = redact_text(content)  # secrets never reach disk or the hash
        data = cleaned.encode("utf-8")
        if not data or len(data) > MAX_IMPORT_BYTES:
            raise ImportRejected("SIZE_OUT_OF_RANGE")
        content_hash = self.evidence.put(tenant_id, data)
        import_id = f"imp-{uuid.uuid4().hex[:20]}"
        with tenant_connection(self.engine, tenant_id) as conn:
            conn.execute(
                text(
                    "INSERT INTO imports (tenant_id, import_id, project_id, kind, filename, "
                    "content_hash, size_bytes, redacted, uploaded_by, uploaded_at) VALUES "
                    "(:t, :i, :p, :k, :f, :h, :n, :r, :u, :at)"
                ),
                {"t": tenant_id, "i": import_id, "p": project_id, "k": kind,
                 "f": safe_filename(filename), "h": content_hash, "n": len(data),
                 "r": cleaned != content, "u": actor, "at": now},
            )  # fmt: skip
        return ImportMeta(
            import_id, kind, safe_filename(filename), content_hash, len(data), cleaned != content
        )

    def read(
        self, *, tenant_id: str, project_id: str, import_id: str, kinds: frozenset[str]
    ) -> bytes:
        """Return verified bytes, or raise ImportRejected with a stable code."""
        with tenant_connection(self.engine, tenant_id) as conn:
            row = conn.execute(
                text("SELECT project_id::text, kind, content_hash FROM imports WHERE import_id=:i"),
                {"i": import_id},
            ).first()
        if row is None:
            raise ImportRejected("IMPORT_NOT_FOUND")  # also another tenant's import (RLS)
        if row[0] != project_id:
            raise ImportRejected("IMPORT_OTHER_PROJECT")
        if row[1] not in kinds:
            raise ImportRejected("IMPORT_KIND_MISMATCH")
        try:
            data = self.evidence.get(tenant_id, row[2])
        except EvidenceIntegrityError as exc:
            raise ImportRejected("IMPORT_INTEGRITY_FAILURE") from exc
        if "sha256:" + hashlib.sha256(data).hexdigest() != row[2]:  # defence in depth
            raise ImportRejected("IMPORT_INTEGRITY_FAILURE")
        return data
