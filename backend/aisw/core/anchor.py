"""Externally witnessed audit-chain anchors (ADR-042): ``python -m aisw.core.anchor`` (hourly timer).

The audit chain is hash-linked, so an edit is detectable, but someone with database rights could
rewrite the whole chain consistently. An anchor is a signed statement of a tenant's chain head
(sequence number and event hash) handed to a witness outside the database. Verification checks
that each anchored event is still the one that was anchored, that the signature verifies, and that
the witness still holds the statement: a rewritten history no longer matches its anchors.

``LocalFileWitness`` is a dev/test emulator: an append-only, hash-chained log file. A production
witness (an RFC 3161 time-stamping authority, a transparency log or a write-once bucket in another
account) needs the ``audit-anchor-witness`` sign-off.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import Connection, Engine, text

from aisw.authz.signing import ManifestSigner, SignatureVerifier
from aisw.contracts.base import canonical_hash, canonical_json
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection

DOMAIN = "aisw-audit-anchor-v1"
SYSTEM_ACTOR = "system:audit-anchor"


class Witness(Protocol):
    witness_id: str

    def witness(self, statement: bytes) -> dict[str, Any]: ...
    def confirm(self, statement: bytes, receipt: Mapping[str, Any]) -> bool: ...


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class LocalFileWitness:
    """Append-only, hash-chained log outside the database (dev/test only)."""

    witness_id = "local-file-witness"

    def __init__(self, path: Path) -> None:
        self.path = path

    def _lines(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(ln) for ln in self.path.read_text().splitlines() if ln.strip()]

    def witness(self, statement: bytes) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.seek(0)
            lines = [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]
            prev = lines[-1]["entry_hash"] if lines else "sha256:" + "0" * 64
            entry = {"index": len(lines), "statement_hash": _sha(statement), "prev": prev,
                     "at": datetime.now(UTC).isoformat()}  # fmt: skip
            entry["entry_hash"] = canonical_hash(entry)
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return {"index": entry["index"], "entry_hash": entry["entry_hash"]}

    def confirm(self, statement: bytes, receipt: Mapping[str, Any]) -> bool:
        lines = self._lines()
        prev = "sha256:" + "0" * 64
        for i, e in enumerate(lines):
            body = {k: e[k] for k in ("index", "statement_hash", "prev", "at")}
            if e["index"] != i or e["prev"] != prev or canonical_hash(body) != e["entry_hash"]:
                return False  # the witness log itself was edited
            prev = e["entry_hash"]
        at = receipt.get("index")
        if not isinstance(at, int) or not 0 <= at < len(lines):
            return False
        entry = lines[at]
        return bool(
            entry["entry_hash"] == receipt.get("entry_hash")
            and entry["statement_hash"] == _sha(statement)
        )


def statement(tenant_id: str, seq: int, head_hash: str, anchored_at: datetime) -> bytes:
    return canonical_json({"domain": DOMAIN, "tenant_id": tenant_id, "seq": seq,
                           "head_hash": head_hash, "anchored_at": anchored_at.astimezone(UTC).isoformat()})  # fmt: skip


@dataclass(frozen=True)
class Anchor:
    tenant_id: str
    seq: int
    head_hash: str
    witness_id: str
    anchored_at: datetime


def anchor(engine: Engine, tenant_id: str, signer: ManifestSigner, witness: Witness, now: datetime) -> Anchor | None:  # fmt: skip
    """Anchor the current head; None when there is nothing new since the last anchor."""
    with tenant_connection(engine, tenant_id) as conn:
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:t, 1))"), {"t": tenant_id}
        )
        head = conn.execute(
            text(
                "SELECT seq, event_hash FROM audit_events WHERE tenant_id=:t ORDER BY seq DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).first()
        if head is None:
            return None
        last = conn.execute(
            text(
                "SELECT seq, head_hash FROM audit_anchors WHERE tenant_id=:t ORDER BY seq DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).first()
        if last is not None and last[0] + 1 >= head[0]:
            return None  # only this job's own record of the previous anchor is newer
        body = statement(tenant_id, head[0], head[1], now)
        signed = signer.sign_detached(body)
        receipt = witness.witness(body)
        conn.execute(
            text(
                "INSERT INTO audit_anchors (tenant_id, seq, head_hash, statement_hash, key_id, "
                "signature, witness_id, receipt, anchored_at) VALUES (:t, :s, :h, :sh, :k, :sig, "
                ":w, CAST(:r AS jsonb), :at)"
            ),
            {"t": tenant_id, "s": head[0], "h": head[1], "sh": _sha(body), "k": signed.key_id,
             "sig": signed.signature, "w": witness.witness_id, "r": json.dumps(receipt), "at": now},
        )  # fmt: skip
        append_audit(
            conn, tenant_id=tenant_id, actor=SYSTEM_ACTOR, action="audit.anchor",
            resource=f"audit-anchor:{head[0]}", result="SUCCESS", correlation_id=f"anchor-{head[0]}",
            after_hash=_sha(body), now=now,
        )  # fmt: skip
    return Anchor(tenant_id, head[0], head[1], witness.witness_id, now)


@dataclass
class AnchorReport:
    ok: bool
    checked: int
    latest_seq: int | None = None
    latest_at: datetime | None = None
    witness_id: str | None = None
    problems: list[str] = field(default_factory=list)


def verify_anchors(
    conn: Connection, tenant_id: str, verifier: SignatureVerifier | None, witness: Witness | None
) -> AnchorReport:
    rows = conn.execute(
        text(
            "SELECT a.seq, a.head_hash, a.statement_hash, a.key_id, a.signature, a.witness_id, "
            "a.receipt, a.anchored_at, e.event_hash FROM audit_anchors a LEFT JOIN audit_events e "
            "ON e.tenant_id=a.tenant_id AND e.seq=a.seq WHERE a.tenant_id=:t ORDER BY a.seq"
        ),
        {"t": tenant_id},
    ).all()
    problems: list[str] = []
    for seq, head, sh, key_id, sig, wid, receipt, at, current in rows:
        body = statement(tenant_id, seq, head, at)
        if current != head:
            problems.append(f"ANCHORED_EVENT_CHANGED:{seq}")
        if _sha(body) != sh:
            problems.append(f"STATEMENT_MISMATCH:{seq}")
        if verifier is None or not verifier.verify(key_id, body, sig):
            problems.append(f"SIGNATURE_NOT_VERIFIED:{seq}")
        if witness is None or witness.witness_id != wid:
            problems.append(f"WITNESS_UNAVAILABLE:{seq}")
        elif not witness.confirm(body, receipt):
            problems.append(f"WITNESS_MISMATCH:{seq}")
    last = rows[-1] if rows else None
    return AnchorReport(
        ok=bool(rows) and not problems, checked=len(rows),
        latest_seq=last[0] if last else None, latest_at=last[7] if last else None,
        witness_id=last[5] if last else None, problems=problems,
    )  # fmt: skip


def witness_from_settings(path: Path | None, kind: str) -> Witness | None:
    return LocalFileWitness(path) if kind == "local_file" and path is not None else None


def main(argv: list[str] | None = None) -> int:
    from aisw.api.container import build_container  # noqa: PLC0415
    from aisw.core.config import get_settings  # noqa: PLC0415
    from aisw.core.db import make_engine  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="python -m aisw.core.anchor")
    ap.add_argument("--tenant", action="append", default=[], help="tenant to anchor (repeatable)")
    args = ap.parse_args(argv)
    settings = get_settings()
    tenants = args.tenant or [
        t.strip() for t in (settings.anchor_tenants or "").split(",") if t.strip()
    ]
    if not tenants:
        print("no tenants: pass --tenant or set AISW_ANCHOR_TENANTS", file=sys.stderr)
        return 2
    witness = witness_from_settings(settings.audit_witness_path, settings.audit_witness)
    if witness is None:
        print("no audit witness is configured (AISW_AUDIT_WITNESS)", file=sys.stderr)
        return 2
    if settings.database_url is None:
        print("AISW_DATABASE_URL is required", file=sys.stderr)
        return 2
    engine = make_engine(settings.database_url.get_secret_value())
    c = build_container(settings, engine)
    if c.signer is None:
        print("no signer is configured: anchors must be signed", file=sys.stderr)
        return 2
    for tenant in tenants:
        a = anchor(engine, tenant, c.signer, witness, c.clock())
        print(json.dumps({"tenant_id": tenant, "anchored_seq": a.seq if a else None}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
