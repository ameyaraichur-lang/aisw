"""Scheduled retention checks: ``python -m aisw.evidence.retention_schedule`` (daily timer).

Every check builds the dry-run plan and records it. Nothing moves unless automatic execution is
switched on (AISW_RETENTION_AUTO_EXECUTE) AND an earlier check saw the identical plan hash at least
AISW_RETENTION_CONFIRM_HOURS before: the same items, holds and shared blobs, twice, a day apart.
Execution is the same soft purge to quarantine as a manual one, recorded as the scheduler.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Engine, text

from aisw.contracts.base import canonical_hash
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.evidence import retention
from aisw.evidence.store import EvidenceStore

log = logging.getLogger("aisw.retention")
SYSTEM_ACTOR = "system:retention-scheduler"


@dataclass(frozen=True)
class CheckResult:
    tenant_id: str
    plan_hash: str
    items: int
    blobs: int
    bytes: int
    held_runs: int
    outcome: str
    moved_blobs: int = 0


def run_check(
    engine: Engine, store: EvidenceStore, tenant_id: str, now: datetime, *,
    import_retention_days: int, auto_execute: bool, confirm_hours: int,
) -> CheckResult:  # fmt: skip
    plan = retention.build_plan(engine, tenant_id, now, import_retention_days=import_retention_days)
    s = plan.summary()
    moved = 0
    if not plan.items:
        outcome = "NOTHING_DUE"
    elif not auto_execute:
        outcome = "DUE"
    else:
        with tenant_connection(engine, tenant_id) as conn:
            first_seen = conn.execute(
                text(
                    "SELECT min(checked_at) FROM retention_checks WHERE plan_hash=:h "
                    "AND outcome IN ('DUE','AWAITING_CONFIRMATION')"
                ),
                {"h": plan.plan_hash},
            ).scalar()
        if first_seen is None or now - first_seen < timedelta(hours=confirm_hours):
            outcome = "AWAITING_CONFIRMATION"
        else:
            reason = f"scheduled retention: plan unchanged since {first_seen.isoformat()}"
            try:
                out = retention.execute(
                    engine, store, plan, actor=SYSTEM_ACTOR, reason=reason, now=now,
                    import_retention_days=import_retention_days,
                )  # fmt: skip
                outcome, moved = "EXECUTED", out.moved_blobs
            except retention.PlanChanged:
                outcome = "PLAN_CHANGED"
    with tenant_connection(engine, tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO retention_checks (tenant_id, checked_at, plan_hash, items, blobs, "
                "bytes, held_runs, outcome, auto_execute) VALUES (:t, :n, :h, :i, :b, :by, :hr, "
                ":o, :a)"
            ),
            {"t": tenant_id, "n": now, "h": plan.plan_hash, "i": len(plan.items), "b": s["blobs"],
             "by": s["bytes"], "hr": len(plan.held_runs), "o": outcome, "a": auto_execute},
        )  # fmt: skip
        append_audit(
            conn, tenant_id=tenant_id, actor=SYSTEM_ACTOR,
            action="retention.purge" if outcome == "EXECUTED" else "retention.check",
            resource=f"plan:{plan.plan_hash}", result="SUCCESS",
            correlation_id=f"retention-{now.strftime('%Y%m%dT%H%M%S')}",
            after_hash=canonical_hash({"outcome": outcome, "items": len(plan.items)}),
        )  # fmt: skip
    return CheckResult(
        tenant_id, plan.plan_hash, len(plan.items), s["blobs"], s["bytes"], len(plan.held_runs),
        outcome, moved,
    )  # fmt: skip


def main(argv: list[str] | None = None) -> int:
    from aisw.api.container import build_container  # noqa: PLC0415
    from aisw.core.config import get_settings  # noqa: PLC0415
    from aisw.core.db import make_engine  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="python -m aisw.evidence.retention_schedule")
    ap.add_argument("--tenant", action="append", default=[], help="tenant to check (repeatable)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    tenants = args.tenant or [
        t.strip() for t in (settings.retention_tenants or "").split(",") if t.strip()
    ]
    if not tenants:
        print("no tenants: pass --tenant or set AISW_RETENTION_TENANTS", file=sys.stderr)
        return 2
    if settings.database_url is None:
        print("AISW_DATABASE_URL is required", file=sys.stderr)
        return 2
    engine = make_engine(settings.database_url.get_secret_value())
    c = build_container(settings, engine)
    if c.evidence is None:
        print("evidence storage is not configured", file=sys.stderr)
        return 2
    for tenant in tenants:
        r = run_check(
            engine, c.evidence, tenant, c.clock(),
            import_retention_days=settings.evidence_retention_days,
            auto_execute=settings.retention_auto_execute,
            confirm_hours=settings.retention_confirm_hours,
        )  # fmt: skip
        print(json.dumps(r.__dict__, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
