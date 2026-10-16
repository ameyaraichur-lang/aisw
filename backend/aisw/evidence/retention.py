"""Evidence retention: plan (dry-run) -> hash-pinned execute -> soft purge.

* A run's evidence becomes eligible when the run is finished, its manifest's retention period has
  elapsed since the run last changed, and no legal hold is active.
* A content-addressed blob is moved only if EVERY reference to it (evidence of any run, uploaded
  imports) is eligible; a blob shared with something still retained is kept.
* Execution needs the hash of the plan the caller reviewed; if anything changed the plan hash
  differs and nothing is touched. Blobs are moved to a quarantine folder, never deleted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, text

from aisw.contracts.base import canonical_hash
from aisw.core.db import tenant_connection
from aisw.evidence.store import EvidenceStore

TERMINAL = ("CLOSED", "FAILED", "CANCELLED", "EXPIRED")


@dataclass(frozen=True)
class Item:
    kind: str  # EVIDENCE | IMPORT
    ref: str
    content_hash: str
    size_bytes: int
    run_id: str | None


@dataclass(frozen=True)
class Plan:
    tenant_id: str
    as_of: datetime
    items: list[Item]  # only items whose blob will actually move
    kept_shared: list[str]  # blob hashes kept because something retained still uses them
    held_runs: list[str]
    plan_hash: str

    def summary(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of.isoformat(), "plan_hash": self.plan_hash,
            "items": [i.__dict__ for i in self.items],
            "blobs": len({i.content_hash for i in self.items}),
            "bytes": sum({i.content_hash: i.size_bytes for i in self.items}.values()),
            "kept_shared": self.kept_shared, "held_runs": self.held_runs,
            "mode": "DRY_RUN: nothing has been changed",
        }  # fmt: skip


def _eligible_runs(conn: Connection, now: datetime) -> tuple[set[str], set[str]]:
    rows = conn.execute(
        text(
            "SELECT r.run_id, r.state, r.updated_at, (m.body->>'evidence_retention_days')::int, "
            "EXISTS (SELECT 1 FROM retention_holds h WHERE h.run_id=r.run_id AND h.released_at IS NULL) "
            "FROM assessment_runs r JOIN scope_manifests m ON m.manifest_id=r.manifest_id"
        )
    ).all()
    eligible: set[str] = set()
    held: set[str] = set()
    for run_id, state, updated, days, is_held in rows:
        if is_held:
            held.add(run_id)
        elif state in TERMINAL and updated + timedelta(days=days) <= now:
            eligible.add(run_id)
    return eligible, held


def build_plan(
    engine: Engine, tenant_id: str, now: datetime, *, import_retention_days: int
) -> Plan:
    with tenant_connection(engine, tenant_id) as conn:
        eligible, held = _eligible_runs(conn, now)
        ev = conn.execute(
            text(
                "SELECT e.evidence_ref, e.run_id, e.content_hash, e.size_bytes, a.executed_at "
                "FROM evidence_artifacts e LEFT JOIN retention_actions a "
                "ON a.kind='EVIDENCE' AND a.ref=e.evidence_ref"
            )
        ).all()
        # an import is purgeable when every run that used it is eligible (or none did and it is old)
        used: dict[str, set[str]] = {}
        for imp_id, run_id in conn.execute(
            text("SELECT params->>'import_id', run_id FROM run_tasks WHERE params ? 'import_id'")
        ):
            used.setdefault(imp_id, set()).add(run_id)
        done_imports = {
            r[0]
            for r in conn.execute(text("SELECT ref FROM retention_actions WHERE kind='IMPORT'"))
        }
        imports = conn.execute(
            text("SELECT import_id, content_hash, size_bytes, uploaded_at FROM imports")
        ).all()

    candidates: list[Item] = []
    blocking: set[str] = set()  # hashes still referenced by something that stays
    for ref, run_id, h, size, purged in ev:
        if purged is not None:
            continue
        if run_id in eligible:
            candidates.append(Item("EVIDENCE", ref, h, size, run_id))
        else:
            blocking.add(h)
    for imp_id, h, size, uploaded in imports:
        if imp_id in done_imports:
            continue
        runs = used.get(imp_id, set())
        ok = (runs <= eligible) if runs else uploaded + timedelta(days=import_retention_days) <= now
        if ok:
            candidates.append(Item("IMPORT", imp_id, h, size, None))
        else:
            blocking.add(h)
    keep = sorted({c.content_hash for c in candidates} & blocking)
    items = [c for c in candidates if c.content_hash not in blocking]
    items.sort(key=lambda i: (i.kind, i.ref))
    body = {
        "tenant": tenant_id,
        "items": [i.__dict__ for i in items],
        "held": sorted(held),
        "kept": keep,
    }
    return Plan(tenant_id, now, items, keep, sorted(held), canonical_hash(body))


@dataclass(frozen=True)
class Outcome:
    moved_blobs: int
    missing_blobs: int
    items: int


def execute(
    engine: Engine, store: EvidenceStore, plan: Plan, *, actor: str, reason: str, now: datetime,
    import_retention_days: int,
) -> Outcome:  # fmt: skip
    """Re-plan under the same clock and refuse unless the plan the caller approved is unchanged."""
    current = build_plan(engine, plan.tenant_id, now, import_retention_days=import_retention_days)
    if current.plan_hash != plan.plan_hash:
        raise PlanChanged()
    moved = missing = 0
    done: dict[str, bool] = {}
    with tenant_connection(engine, plan.tenant_id) as conn:
        for it in current.items:
            if it.content_hash not in done:
                done[it.content_hash] = store.quarantine(plan.tenant_id, it.content_hash)
                moved += done[it.content_hash]
                missing += not done[it.content_hash]
            conn.execute(
                text(
                    "INSERT INTO retention_actions (tenant_id, plan_hash, kind, ref, content_hash, "
                    "size_bytes, quarantined, executed_by, executed_at, reason) VALUES (:t, :ph, :k, "
                    ":ref, :h, :s, :q, :by, :n, :why)"
                ),
                {"t": plan.tenant_id, "ph": current.plan_hash, "k": it.kind, "ref": it.ref,
                 "h": it.content_hash, "s": it.size_bytes, "q": done[it.content_hash], "by": actor,
                 "n": now, "why": reason},
            )  # fmt: skip
    return Outcome(moved, missing, len(current.items))


class PlanChanged(Exception):  # noqa: N818
    """The state changed since the plan was reviewed: nothing was touched."""
