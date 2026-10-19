"""Manifests signed through the Transit KMS survive rotation; revocation and outages fail closed."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aisw.api.app import create_app
from aisw.api.container import build_container
from aisw.authz.service import ScopeDenied
from aisw.authz.signing import KeyRing, SigningError, signing_payload
from aisw.authz.transit import TransitClient, TransitSigner
from aisw.core.config import Environment, Settings
from aisw.core.db import tenant_connection
from tests.conftest import auth
from tests.kms_emulator import TransitEmulator
from tests.support import Env, make_env

pytestmark = pytest.mark.security
KEY = "aisw-manifests"


@pytest.fixture()
def emu() -> Iterator[TransitEmulator]:
    with TransitEmulator() as e:
        e.create(KEY)
        yield e


def use_transit(env: Env, emu: TransitEmulator, revoked: tuple[str, ...] = ()) -> KeyRing:
    app = TransitClient(emu.addr, KEY, emu.app_token, env=Environment.TEST)
    ring = KeyRing(revoked=revoked, loader=app.public_keys)
    env.service.signer = TransitSigner(app, ring)
    env.service.keyring = ring
    env.gateway.verifier = ring
    return ring


def test_manifest_approved_before_rotation_still_launches(
    app_engine: Engine, emu: TransitEmulator
) -> None:
    env = make_env(app_engine)
    use_transit(env, emu)
    old = env.approved()
    assert old.key_id == f"transit.{KEY}.v1"
    admin = TransitClient(emu.addr, KEY, emu.admin_token, env=Environment.TEST)
    admin.rotate()
    new = env.approved()
    assert new.key_id == f"transit.{KEY}.v2"  # supersedes the old one for new launches
    admin.retire_below(2)
    use_transit(env, emu)  # as after a restart: keys come only from the KMS
    assert env.launch(new).permit.permit_id
    with tenant_connection(app_engine, env.tenant) as c:
        stored = c.execute(text("SELECT key_id FROM scope_manifests WHERE manifest_id=:m"),
                           {"m": old.manifest_id}).scalar_one()  # fmt: skip
    assert stored == f"transit.{KEY}.v1"
    payload = signing_payload(
        tenant_id=old.body.tenant_id, project_id=old.body.project_id, manifest_id=old.manifest_id,
        version=old.version, canonical_hash=old.canonical_hash,
    )  # fmt: skip
    ring = use_transit(env, emu)
    assert old.signature and ring.verify(stored, payload, old.signature)


def test_revoked_key_version_blocks_launch(app_engine: Engine, emu: TransitEmulator) -> None:
    env = make_env(app_engine)
    use_transit(env, emu)
    m = env.approved()
    use_transit(env, emu, revoked=(f"transit.{KEY}.v1",))
    with pytest.raises(ScopeDenied) as exc:
        env.launch(m)
    assert exc.value.reason_codes == ["BAD_SIGNATURE"]


def test_kms_outage_refuses_approval_without_changing_state(
    app_engine: Engine, emu: TransitEmulator
) -> None:
    env = make_env(app_engine)
    use_transit(env, emu)
    approved = env.approved()
    draft = env.draft()
    env.service.preflight(env.operator, draft.manifest_id, cid="t")
    emu.down = True
    with pytest.raises(SigningError):
        env.service.approve(env.approver, draft.manifest_id, acknowledge_active_adapters=frozenset(),
                            cid="t")  # fmt: skip
    with tenant_connection(app_engine, env.tenant) as c:
        rows: dict[str, str] = dict(c.execute(text("SELECT manifest_id::text, status FROM scope_manifests "
                                   "WHERE project_id=:p"), {"p": env.project_id}).all())  # fmt: skip
    assert (
        rows[str(draft.manifest_id)] != "APPROVED" and rows[str(approved.manifest_id)] == "APPROVED"
    )
    assert env.launch(approved).permit.permit_id  # verification is local: launches continue


def test_container_builds_the_transit_signer_and_api_maps_outage_to_503(
    app_engine: Engine, emu: TransitEmulator, tmp_path: Path
) -> None:
    tok = tmp_path / "kms-token"
    tok.write_text(emu.app_token)
    os.chmod(tok, 0o600)
    s = Settings(env="test", dev_auth_stub=True, signing_backend="transit", kms_addr=emu.addr,
                 kms_key=KEY, kms_token_file=tok)  # fmt: skip
    c = build_container(s, app_engine)
    assert isinstance(c.signer, TransitSigner) and c.keyring is not None
    assert c.keyring.key_ids() == [f"transit.{KEY}.v1"]
    api = TestClient(create_app(s, app_engine, c))

    def call(method: str, path: str, user: str, body: dict[str, Any]) -> Any:
        return api.request(method, f"/api/v1{path}", json=body,
                           headers={**auth(user), "Idempotency-Key": uuid.uuid4().hex})  # fmt: skip

    p = call("POST", "/projects", "alice", {"name": f"kms-{uuid.uuid4().hex[:8]}",
                                            "environment": "test"}).json()  # fmt: skip
    pid = p["project_id"]
    assert call("POST", "/inventory", "alice", {
        "project_id": pid, "kind": "asset_group", "selector": "fixture-group-1",
        "expected_assets": ["host-1"]}).status_code == 201  # fmt: skip
    body = {
        "project_id": pid, "targets": [{"kind": "asset_group", "selector": "fixture-group-1"}],
        "domains": ["host"], "allowed_adapters": ["fixture"],
        "profiles": {"fixture": {"profile_id": "FIXTURE_BASELINE", "profile_class": "READ_ONLY"}},
        "evidence_retention_days": 30, "policy_version": "fixture-baseline:1.0.0",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    }  # fmt: skip
    mid = call("POST", "/scope-manifests", "alice", body).json()["manifest"]["manifest_id"]
    assert call("POST", f"/scope-manifests/{mid}/preflight", "alice", {}).status_code == 200
    emu.down = True
    r = call("POST", f"/scope-manifests/{mid}/approve", "bob", {})
    assert r.status_code == 503 and r.json() == {"error": "signer_unavailable"}
    emu.down = False
    r = call("POST", f"/scope-manifests/{mid}/approve", "bob", {})
    assert r.status_code == 200 and r.json()["key_id"] == f"transit.{KEY}.v1"
