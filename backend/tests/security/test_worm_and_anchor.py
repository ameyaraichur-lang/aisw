"""Write-once evidence replica and externally witnessed audit anchors (ADR-042). Emulators only:
no bucket, time-stamping authority or network is used."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, text

from aisw.authz.signing import KeyRing, LocalKeySigner
from aisw.core import anchor as anc
from aisw.core.audit import _hash_fields, _iso, append_audit, verify_chain
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from aisw.evidence.store import EvidenceIntegrityError
from aisw.evidence.worm import LocalObjectLockEmulator, ObjectLocked, WormEvidenceStore
from tests.slice import Slice

pytestmark = pytest.mark.security
T0 = datetime(2026, 10, 1, tzinfo=UTC)
KEY = "tenant-a/" + "ab" * 32


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


# ------------------------------------------------------------------ write-once replica
def test_the_emulator_enforces_compliance_retention(tmp_path: Path) -> None:
    clock = Clock()
    lock = LocalObjectLockEmulator(tmp_path / "worm", clock)
    lock.put(KEY, b"evidence", T0 + timedelta(days=30))
    assert lock.get(KEY) == b"evidence" and lock.lock(KEY).retain_until == T0 + timedelta(days=30)  # type: ignore[union-attr]
    with pytest.raises(ObjectLocked, match="different content"):
        lock.put(KEY, b"forged", T0 + timedelta(days=30))
    lock.put(KEY, b"evidence", T0 + timedelta(days=10))  # same bytes, shorter date: not shortened
    assert lock.lock(KEY).retain_until == T0 + timedelta(days=30)  # type: ignore[union-attr]
    with pytest.raises(ObjectLocked, match="only be extended"):
        lock.extend(KEY, T0 + timedelta(days=1))
    with pytest.raises(ObjectLocked, match="retained until"):
        lock.delete(KEY)
    lock.extend(KEY, T0 + timedelta(days=40))
    clock.now = T0 + timedelta(days=41)
    lock.delete(KEY)
    assert lock.lock(KEY) is None
    with pytest.raises(ObjectLocked, match="invalid object key"):
        lock.put("../escape/" + "ab" * 32, b"x", T0)


def test_a_store_write_is_complete_only_when_the_replica_holds_it(tmp_path: Path) -> None:
    clock = Clock()
    replica = LocalObjectLockEmulator(tmp_path / "worm", clock)
    store = WormEvidenceStore(tmp_path / "live", replica, retain_days=30, clock=clock)
    h = store.put("tenant-a", b"raw scan output")
    info = store.lock("tenant-a", h)
    assert store.verify("tenant-a", h) and info and info.retain_until == T0 + timedelta(days=30)

    live = store._path("tenant-a", h)  # noqa: SLF001
    live.chmod(0o640)
    live.write_bytes(b"tampered")
    assert not store.verify("tenant-a", h)
    assert store.restore("tenant-a", h) is True and store.get("tenant-a", h) == b"raw scan output"
    assert store.restore("tenant-a", h) is False  # nothing to repair

    assert store.quarantine("tenant-a", h)  # a retention purge is never undone from the replica
    assert store.restore("tenant-a", h) is False
    with pytest.raises(EvidenceIntegrityError):
        store.get("tenant-a", h)

    other = WormEvidenceStore(tmp_path / "live2", replica, retain_days=30, clock=clock)
    h2 = "sha256:" + __import__("hashlib").sha256(b"second").hexdigest()
    replica.put(WormEvidenceStore.key("tenant-a", h2), b"squatter", T0 + timedelta(days=1))
    with pytest.raises(EvidenceIntegrityError, match="replica refused"):
        other.put("tenant-a", b"second")


def test_a_run_writes_every_artifact_to_the_replica(
    app_engine: Engine, worker_engine: Engine, tmp_path: Path
) -> None:
    replica = LocalObjectLockEmulator(tmp_path / "worm")
    store = WormEvidenceStore(tmp_path / "evidence", replica, retain_days=30)
    sl = Slice(app_engine, worker_engine, tmp_path / "evidence", evidence=store)
    _, _, run_id = sl.full_run(["host-1", "host-2", "host-3"])
    sl.drain()
    rows = sl.sql("SELECT content_hash FROM evidence_artifacts WHERE run_id=:r", r=run_id)
    assert rows and all(store.replica_ok("tenant-a", h) for (h,) in rows)
    assert all(store.lock("tenant-a", h).mode == "COMPLIANCE" for (h,) in rows)  # type: ignore[union-attr]


def test_emulators_are_refused_in_production_and_need_their_paths(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="dev and test only"):
        Settings(
            env="prod",
            evidence_worm_backend="emulator",
            evidence_worm_dir=tmp_path,
            evidence_dir=tmp_path,
        )
    with pytest.raises(ValidationError, match="requires evidence_worm_dir"):
        Settings(env="test", evidence_worm_backend="emulator")
    with pytest.raises(ValidationError, match="dev and test only"):
        Settings(env="prod", audit_witness="local_file", audit_witness_path=tmp_path / "w.log")
    with pytest.raises(ValidationError, match="requires audit_witness_path"):
        Settings(env="test", audit_witness="local_file")


# ------------------------------------------------------------------ audit anchors
def _log(engine: Engine, tenant: str, n: int) -> None:
    for i in range(n):
        with tenant_connection(engine, tenant) as c:
            append_audit(c, tenant_id=tenant, actor="alice", action=f"act.{i}", resource="res:x",
                         result="SUCCESS", correlation_id=f"cid-{i}")  # fmt: skip


def _report(engine: Engine, tenant: str, ring: KeyRing | None, witness: Any) -> anc.AnchorReport:
    with tenant_connection(engine, tenant) as c:
        return anc.verify_anchors(c, tenant, ring, witness)


@pytest.fixture()
def keys() -> tuple[LocalKeySigner, KeyRing]:
    signer = LocalKeySigner.generate("anchor-key")
    return signer, KeyRing.from_signer(signer)


def test_anchors_are_signed_witnessed_and_only_made_when_something_is_new(
    app_engine: Engine, uid: str, tmp_path: Path, keys: tuple[LocalKeySigner, KeyRing]
) -> None:
    signer, ring = keys
    t, witness = f"anchor-{uid}", anc.LocalFileWitness(tmp_path / "witness.log")
    assert anc.anchor(app_engine, t, signer, witness, T0) is None  # empty chain
    _log(app_engine, t, 3)
    a = anc.anchor(app_engine, t, signer, witness, T0)
    assert a is not None and a.seq == 3
    assert (
        anc.anchor(app_engine, t, signer, witness, T0 + timedelta(hours=1)) is None
    )  # only our own record since
    _log(app_engine, t, 2)
    b = anc.anchor(app_engine, t, signer, witness, T0 + timedelta(hours=2))
    assert b is not None and b.seq == 6
    rep = _report(app_engine, t, ring, witness)
    assert (
        rep.ok
        and rep.checked == 2
        and rep.latest_seq == 6
        and rep.witness_id == "local-file-witness"
    )
    with tenant_connection(app_engine, t) as c:
        actions = [
            r[0]
            for r in c.execute(
                text("SELECT action FROM audit_events WHERE tenant_id=:t ORDER BY seq"), {"t": t}
            )
        ]
        assert actions.count("audit.anchor") == 2 and verify_chain(c, t).ok
        with pytest.raises(Exception, match="permission denied"):
            c.execute(
                text("UPDATE audit_anchors SET head_hash=head_hash WHERE tenant_id=:t"), {"t": t}
            )


def test_a_consistently_rewritten_chain_no_longer_matches_its_anchor(
    app_engine: Engine,
    owner_engine: Engine,
    uid: str,
    tmp_path: Path,
    keys: tuple[LocalKeySigner, KeyRing],
) -> None:
    signer, ring = keys
    t, witness = f"rewrite-{uid}", anc.LocalFileWitness(tmp_path / "witness.log")
    _log(app_engine, t, 4)
    assert anc.anchor(app_engine, t, signer, witness, T0) is not None
    with owner_engine.begin() as c:  # a DBA edits event 2 and re-hashes everything after it
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_no_update"))
        rows = c.execute(text(
            "SELECT event_id::text AS event_id, tenant_id, seq, actor, action, resource, before_hash, after_hash, "
            "correlation_id, result, occurred_at, prev_hash FROM audit_events WHERE tenant_id=:t ORDER BY seq"), {"t": t}).mappings().all()  # fmt: skip
        prev = None
        for r in rows:
            ev = {**dict(r), "occurred_at": _iso(r["occurred_at"])}
            if r["seq"] == 2:
                ev["actor"] = "mallory"
            if prev is not None:
                ev["prev_hash"] = prev
            ev["event_hash"] = prev = _hash_fields(ev)
            c.execute(text("UPDATE audit_events SET actor=:a, prev_hash=:p, event_hash=:h WHERE tenant_id=:t AND seq=:s"),
                      {"a": ev["actor"], "p": ev["prev_hash"], "h": ev["event_hash"], "t": t, "s": r["seq"]})  # fmt: skip
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_no_update"))
    with tenant_connection(app_engine, t) as c:
        assert verify_chain(c, t).ok  # the chain alone cannot tell
    rep = _report(app_engine, t, ring, witness)
    assert not rep.ok and rep.problems == ["ANCHORED_EVENT_CHANGED:4"]


def test_a_forged_signature_an_edited_witness_log_or_a_missing_witness_fail(
    app_engine: Engine, uid: str, tmp_path: Path, keys: tuple[LocalKeySigner, KeyRing]
) -> None:
    signer, ring = keys
    t, log = f"witness-{uid}", tmp_path / "witness.log"
    witness = anc.LocalFileWitness(log)
    _log(app_engine, t, 2)
    assert anc.anchor(app_engine, t, signer, witness, T0) is not None
    other = KeyRing.from_signer(LocalKeySigner.generate("anchor-key"))
    assert _report(app_engine, t, other, witness).problems == ["SIGNATURE_NOT_VERIFIED:2"]
    assert _report(app_engine, t, ring, None).problems == ["WITNESS_UNAVAILABLE:2"]
    entry = json.loads(log.read_text())
    log.write_text(json.dumps({**entry, "statement_hash": "sha256:" + "0" * 64}) + "\n")
    assert _report(app_engine, t, ring, witness).problems == ["WITNESS_MISMATCH:2"]


def test_the_audit_page_reports_anchor_state(sl: Slice) -> None:
    body = sl.call("GET", "/api/v1/audit/verify", "erin").json()
    assert body["ok"] is True
    assert body["anchors"]["witness_configured"] is False and body["anchors"]["ok"] is False


def test_the_anchor_job_refuses_to_run_without_tenants_or_a_witness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from aisw.core import config

    monkeypatch.setattr(config, "get_settings", lambda: Settings(env="test"))
    assert anc.main([]) == 2
    assert anc.main(["--tenant", "tenant-a"]) == 2
