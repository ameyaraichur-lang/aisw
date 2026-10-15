from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisw.evidence.ingest import IngestRejected, evidence_ref, prepare
from aisw.evidence.store import EvidenceIntegrityError, EvidenceStore


def test_prepare_redacts_before_hashing_and_flags_it() -> None:
    secret = "password=" + "hunter2hunter2"
    p = prepare({"comment": f"x {secret}", "ok": 1, "api_key": "k" * 20})
    assert b"hunter2" not in p.data and p.redacted
    assert json.loads(p.data)["api_key"] == "[REDACTED]"
    assert not prepare({"ok": 1}).redacted


def test_prepare_is_canonical_and_bounded() -> None:
    assert prepare({"b": 1, "a": 2}).data == prepare({"a": 2, "b": 1}).data == b'{"a":2,"b":1}'
    with pytest.raises(IngestRejected) as e:
        prepare({"blob": "x" * 6_000_000})
    assert e.value.code == "TOO_LARGE"
    with pytest.raises(IngestRejected) as e2:
        prepare({"a": 1}, media_type="application/x-sh")
    assert e2.value.code == "MEDIA_TYPE_NOT_ALLOWED"
    with pytest.raises(IngestRejected):
        prepare({"x": float("nan")})
    with pytest.raises(IngestRejected):
        prepare({"x": object()})


def test_store_is_content_addressed_immutable_and_verifying(tmp_path: Path) -> None:
    s = EvidenceStore(tmp_path)
    h = s.put("tenant-a", b"hello")
    assert s.put("tenant-a", b"hello") == h  # idempotent
    assert s.get("tenant-a", h) == b"hello" and s.verify("tenant-a", h)
    f = next(p for p in tmp_path.rglob("*") if p.is_file())
    assert f.stat().st_mode & 0o007 == 0  # not world-accessible
    f.write_bytes(b"tampered")
    assert not s.verify("tenant-a", h)
    with pytest.raises(EvidenceIntegrityError):
        s.get("tenant-a", h)
    with pytest.raises(EvidenceIntegrityError):  # re-putting the original refuses to paper over it
        s.put("tenant-a", b"hello")


def test_tenants_are_partitioned_and_paths_cannot_escape(tmp_path: Path) -> None:
    s = EvidenceStore(tmp_path)
    h = s.put("tenant-a", b"secret-a")
    with pytest.raises(EvidenceIntegrityError):
        s.get("tenant-b", h)  # same hash, other tenant: not there
    for tenant in ("../x", "a/b", "", ".hidden", "a" * 65):
        with pytest.raises(EvidenceIntegrityError):
            s.put(tenant, b"x")
    for bad in ("sha256:../../etc/passwd", "sha256:" + "G" * 64, "md5:abc", ""):
        with pytest.raises(EvidenceIntegrityError):
            s.get("tenant-a", bad)


def test_evidence_ref_shape_parses() -> None:
    from aisw.contracts.refs import EvidenceRef

    ref = evidence_ref("t", "p", "r", "fixture", "task-1", "raw")
    assert EvidenceRef.parse(ref).path == "fixture/task-1/raw"
