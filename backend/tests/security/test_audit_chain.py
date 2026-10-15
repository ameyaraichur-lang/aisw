"""Audit trail: append-only, hash-chained per tenant, tamper-evident."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from aisw.core.audit import append_audit, verify_chain
from aisw.core.db import tenant_connection

pytestmark = pytest.mark.security


def _log(engine: Engine, tenant: str, n: int, tag: str = "t") -> None:
    for i in range(n):
        with tenant_connection(engine, tenant) as c:
            append_audit(
                c, tenant_id=tenant, actor="alice", action=f"act.{i}", resource=f"res:{tag}",
                result="SUCCESS", correlation_id=f"cid-{tag}-{i}",
            )  # fmt: skip


def test_chain_verifies_and_is_per_tenant(app_engine: Engine, uid: str) -> None:
    ta, tb = f"chain-a-{uid}", f"chain-b-{uid}"
    _log(app_engine, ta, 4)
    _log(app_engine, tb, 2)
    with tenant_connection(app_engine, ta) as c:
        rep = verify_chain(c, ta)
    assert rep.ok and rep.checked == 4
    with tenant_connection(app_engine, tb) as c:
        assert verify_chain(c, tb).checked == 2


def test_app_role_cannot_update_delete_or_truncate(app_engine: Engine, uid: str) -> None:
    t = f"ro-{uid}"
    _log(app_engine, t, 1)
    for sql in (
        "UPDATE audit_events SET actor='mallory'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            with tenant_connection(app_engine, t) as c:
                c.execute(text(sql))


def test_triggers_block_even_the_owner(owner_engine: Engine, uid: str) -> None:
    t = f"own-{uid}"
    with owner_engine.begin() as c:
        c.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": t})
        append_audit(c, tenant_id=t, actor="a", action="x", resource="r", result="SUCCESS",
                     correlation_id="c")  # fmt: skip
    for sql in ("UPDATE audit_events SET actor='m' WHERE tenant_id=:t",
                "DELETE FROM audit_events WHERE tenant_id=:t"):  # fmt: skip
        with pytest.raises(DBAPIError, match="append-only"), owner_engine.begin() as c:
            c.execute(text(sql), {"t": t})


def test_tampering_by_privileged_actor_is_detected(
    app_engine: Engine, owner_engine: Engine, uid: str
) -> None:
    t = f"tamper-{uid}"
    _log(app_engine, t, 5)
    with owner_engine.begin() as c:  # a DBA disables the guard and edits history
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_no_update"))
        c.execute(
            text("UPDATE audit_events SET actor='mallory' WHERE tenant_id=:t AND seq=3"), {"t": t}
        )
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_no_update"))
    with tenant_connection(app_engine, t) as c:
        rep = verify_chain(c, t)
    assert not rep.ok and rep.broken_at_seq == 3 and "altered" in (rep.reason or "")


def test_deleted_event_is_detected(app_engine: Engine, owner_engine: Engine, uid: str) -> None:
    t = f"gap-{uid}"
    _log(app_engine, t, 4)
    with owner_engine.begin() as c:
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_no_update"))
        c.execute(text("DELETE FROM audit_events WHERE tenant_id=:t AND seq=2"), {"t": t})
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_no_update"))
    with tenant_connection(app_engine, t) as c:
        rep = verify_chain(c, t)
    assert not rep.ok and rep.broken_at_seq == 3


def test_database_rejects_broken_linkage(app_engine: Engine, uid: str) -> None:
    t = f"link-{uid}"
    _log(app_engine, t, 2)
    bad = "sha256:" + "f" * 64
    with pytest.raises(DBAPIError, match="linkage"), tenant_connection(app_engine, t) as c:
        c.execute(
            text(
                "INSERT INTO audit_events (tenant_id, seq, actor, action, resource, "
                "correlation_id, result, occurred_at, prev_hash, event_hash) VALUES "
                "(:t, 3, 'a', 'x', 'r', 'c', 'SUCCESS', now(), :p, :p)"
            ),
            {"t": t, "p": bad},
        )
    with pytest.raises(DBAPIError, match="linkage"):  # skipping a sequence number
        with tenant_connection(app_engine, t) as c:
            last = c.execute(
                text("SELECT event_hash FROM audit_events WHERE tenant_id=:t AND seq=2"), {"t": t}
            ).scalar_one()
            c.execute(
                text(
                    "INSERT INTO audit_events (tenant_id, seq, actor, action, resource, "
                    "correlation_id, result, occurred_at, prev_hash, event_hash) VALUES "
                    "(:t, 9, 'a', 'x', 'r', 'c', 'SUCCESS', now(), :p, :p)"
                ),
                {"t": t, "p": last},
            )
