"""Permit renewal for long runs: extends only what a fresh launch would still allow."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.authz.service import ScopeDenied
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Role
from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]
OPERATOR = ActorContext("tenant-a", "alice", frozenset({Role.ASSESSMENT_OPERATOR}))


def permits(sl: Slice, run_id: str) -> list[Any]:
    return sl.sql(
        "SELECT permit_id::text, issued_at, expires_at, revoked_at FROM execution_permits "
        "WHERE run_id=:r ORDER BY issued_at", r=run_id,
    )  # fmt: skip


def renew(sl: Slice, run_id: str) -> str | None:
    svc = sl.container.service
    assert svc is not None
    return svc.renew_permit("tenant-a", run_id, cid="t")


def current(sl: Slice, run_id: str) -> str:
    return str(
        sl.sql("SELECT permit_id::text FROM assessment_runs WHERE run_id=:r", r=run_id)[0][0]
    )


def test_no_renewal_when_the_permit_is_not_close_to_expiry(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    assert renew(sl, run_id) is None and len(permits(sl, run_id)) == 1


def test_a_permit_close_to_expiry_is_renewed_and_the_run_points_at_the_successor(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    first = current(sl, run_id)
    sl.clock.advance(minutes=11)  # inside the 5 minute margin of the 15 minute permit
    new = renew(sl, run_id)
    assert new is not None and new != first and current(sl, run_id) == new
    rows = permits(sl, run_id)
    assert len(rows) == 2 and rows[1][2] - rows[1][1] == timedelta(minutes=15)
    assert ("permit.renew",) in sl.sql(
        "SELECT action FROM audit_events WHERE action='permit.renew'"
    )


def test_a_run_longer_than_one_permit_still_completes(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.clock.advance(minutes=11)
    sl.drain()  # dispatch happens inside the renewal window: renewed, not rejected
    assert sl.status(run_id)["state"] == "REPORT_READY" and sl.executions == 1
    assert len(permits(sl, run_id)) == 2


def test_lapsed_and_revoked_permits_are_never_renewed(sl: Slice) -> None:
    _, _, lapsed = sl.full_run(EXPECTED)
    sl.clock.advance(minutes=16)
    assert renew(sl, lapsed) is None and len(permits(sl, lapsed)) == 1
    sl.drain()
    assert sl.status(lapsed)["state"] == "FAILED" and sl.executions == 0

    _, _, revoked = sl.full_run(EXPECTED)
    svc = sl.container.service
    assert svc is not None
    svc.revoke_permit(OPERATOR, current(sl, revoked), cid="t")
    sl.clock.advance(minutes=11)
    assert renew(sl, revoked) is None and len(permits(sl, revoked)) == 1
    sl.drain()
    assert sl.executions == 0


def test_revocation_covers_every_permit_of_the_run(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.clock.advance(minutes=11)
    renew(sl, run_id)
    svc = sl.container.service
    assert svc is not None
    svc.revoke_permit(OPERATOR, current(sl, run_id), cid="t")
    assert all(r[3] is not None for r in permits(sl, run_id))


def test_renewal_stops_at_the_lifetime_and_count_caps(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.container.gate.policy = sl.container.gate.policy.model_copy(
        update={"permit_max_renewals": 2}
    )
    for _ in range(2):
        sl.clock.advance(minutes=11)
        assert renew(sl, run_id) is not None
    sl.clock.advance(minutes=11)
    with pytest.raises(ScopeDenied) as e:
        renew(sl, run_id)
    assert e.value.reason_codes == ["PERMIT_RENEWAL_LIMIT"]

    _, _, run2 = sl.full_run(EXPECTED)
    sl.container.gate.policy = sl.container.gate.policy.model_copy(
        update={"permit_max_renewals": 99, "permit_max_lifetime": timedelta(minutes=20)}
    )
    sl.clock.advance(minutes=11)
    assert renew(sl, run2) is not None
    first = permits(sl, run2)[0][1]
    assert permits(sl, run2)[-1][2] == first + timedelta(minutes=20)  # clamped to the lifetime cap
    sl.clock.advance(
        minutes=8
    )  # still valid, still inside the margin, but nothing more can be granted
    with pytest.raises(ScopeDenied) as e2:
        renew(sl, run2)
    assert e2.value.reason_codes == ["PERMIT_CANNOT_EXTEND"]


def test_cap_denials_do_not_block_dispatch_with_a_still_valid_permit(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.container.gate.policy = sl.container.gate.policy.model_copy(
        update={"permit_max_renewals": 0}
    )
    sl.clock.advance(minutes=11)  # inside the margin; renewal is refused by the cap
    sl.drain()
    assert sl.status(run_id)["state"] == "REPORT_READY" and sl.executions == 1
    assert len(permits(sl, run_id)) == 1


def test_a_renewed_permit_never_outlives_the_manifest(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid, expires_at=(sl.clock.now + timedelta(minutes=18)).isoformat())
    r = sl.launch(pid, m)
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]
    sl.clock.advance(minutes=11)
    assert renew(sl, run_id) is not None
    assert permits(sl, run_id)[-1][2] <= sl.clock.now - timedelta(minutes=11) + timedelta(
        minutes=18
    )


def test_renewal_is_refused_when_the_launch_policy_no_longer_passes(sl: Slice) -> None:
    pid, m, run_id = sl.full_run(EXPECTED)
    svc = sl.container.service
    assert svc is not None
    svc.revoke_manifest(
        OPERATOR.__class__("tenant-a", "bob", frozenset({Role.APPROVER})), m["manifest_id"], cid="t"
    )
    sl.clock.advance(minutes=11)
    with pytest.raises(ScopeDenied) as e:
        renew(sl, run_id)
    assert "MANIFEST_NOT_APPROVED" in e.value.reason_codes
    sl.drain()  # the worker turns the denial into a rejected task: nothing runs
    assert sl.status(run_id)["state"] == "FAILED" and sl.executions == 0
    codes = [
        c
        for e in sl.events(run_id)
        if e["type"] == "task.failed"
        for c in e["payload"]["error_codes"]
    ]
    assert (
        any(c.startswith("PERMIT_RENEWAL_DENIED:") for c in codes)
        or "MANIFEST_NOT_APPROVED" in codes
    )


def test_finished_or_cancelled_runs_are_not_renewable(sl: Slice) -> None:
    _, _, done = sl.full_run(EXPECTED)
    sl.drain()
    sl.clock.advance(minutes=11)
    with pytest.raises(ScopeDenied) as e:
        renew(sl, done)
    assert e.value.reason_codes == ["RUN_NOT_RENEWABLE"]


def test_other_tenants_cannot_renew_and_the_database_refuses_foreign_permits(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.clock.advance(minutes=11)
    svc = sl.container.service
    assert svc is not None
    assert svc.renew_permit("tenant-b", run_id, cid="t") is None  # RLS: the run is invisible
    assert len(permits(sl, run_id)) == 1
    _, _, other = sl.full_run(EXPECTED)
    foreign = current(sl, other)
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
        c.execute(
            text("UPDATE assessment_runs SET permit_id=:p WHERE run_id=:r"),
            {"p": foreign, "r": run_id},
        )  # another run's permit: refused by the trigger
