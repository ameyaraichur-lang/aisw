"""Transit KMS signer, key ring refresh/revocation and the rotation drill (ADR-027)."""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aisw.authz.drill import passed, render_markdown, report, run_drill
from aisw.authz.signing import KeyRing, LocalKeySigner, SigningError
from aisw.authz.transit import (
    TransitClient,
    TransitSigner,
    read_token_file,
    transit_from_settings,
)
from aisw.core.config import Environment, Settings
from tests.kms_emulator import TransitEmulator

KEY = "aisw-manifests"


@pytest.fixture()
def emu() -> Iterator[TransitEmulator]:
    with TransitEmulator() as e:
        e.create(KEY)
        yield e


def client(emu: TransitEmulator, token: str | None = None, **kw: Any) -> TransitClient:
    return TransitClient(emu.addr, KEY, token or emu.app_token, env=Environment.TEST, **kw)


def token_file(tmp_path: Path, token: str, mode: int = 0o600) -> Path:
    p = tmp_path / "kms-token"
    p.write_text(token + "\n")
    os.chmod(p, mode)
    return p


def test_sign_and_verify_locally(emu: TransitEmulator) -> None:
    c = client(emu)
    ring = KeyRing(loader=c.public_keys)
    signed = TransitSigner(c, ring).sign_detached(b"payload")
    assert signed.key_id == f"transit.{KEY}.v1"
    assert ring.verify(signed.key_id, b"payload", signed.signature)
    assert not ring.verify(signed.key_id, b"payload!", signed.signature)
    assert emu.app_token not in repr(c)


def test_app_token_cannot_administer_the_key(emu: TransitEmulator) -> None:
    c = client(emu)
    with pytest.raises(SigningError, match="403"):
        c.rotate()
    with pytest.raises(SigningError, match="403"):
        c.retire_below(1)
    with pytest.raises(SigningError, match="403"):
        client(emu, token="emu.wrong").sign(b"x")  # noqa: S106 - not a credential


def test_rotation_is_picked_up_and_old_versions_keep_verifying(emu: TransitEmulator) -> None:
    app, admin = client(emu), client(emu, emu.admin_token)
    ring = KeyRing(loader=app.public_keys)
    signer = TransitSigner(app, ring)
    v1 = signer.sign_detached(b"one")
    assert admin.rotate() == 2
    v2 = signer.sign_detached(b"two")  # forced reload of the just-rotated version
    assert v2.key_id.endswith(".v2")
    assert ring.verify(v1.key_id, b"one", v1.signature) and ring.verify(
        v2.key_id, b"two", v2.signature
    )
    admin.retire_below(2)
    with pytest.raises(SigningError, match="400"):
        app.sign(b"old", version=1)
    assert KeyRing(loader=app.public_keys).verify(v1.key_id, b"one", v1.signature)


def test_revoked_versions_never_verify_or_sign(emu: TransitEmulator) -> None:
    app = client(emu)
    revoked = f"transit.{KEY}.v1"
    ring = KeyRing(revoked=[revoked], loader=app.public_keys)
    with pytest.raises(SigningError, match="revoked"):
        TransitSigner(app, ring).sign_detached(b"x")
    good = TransitSigner(app, KeyRing(loader=app.public_keys)).sign_detached(b"x")
    assert not ring.verify(good.key_id, b"x", good.signature)
    assert revoked not in ring.key_ids()


def test_a_bad_signature_from_the_kms_is_refused(emu: TransitEmulator) -> None:
    app = client(emu)
    emu.tamper_next_signature = True
    with pytest.raises(SigningError, match="does not verify"):
        TransitSigner(app, KeyRing(loader=app.public_keys)).sign_detached(b"x")


def test_kms_outage_blocks_signing_but_not_verification(emu: TransitEmulator) -> None:
    app = client(emu)
    ring = KeyRing(loader=app.public_keys)
    signed = TransitSigner(app, ring).sign_detached(b"x")
    emu.down = True
    with pytest.raises(SigningError, match="503"):
        TransitSigner(app, ring).sign_detached(b"y")
    assert ring.verify(signed.key_id, b"x", signed.signature)
    cold = KeyRing(loader=app.public_keys)  # started while the KMS is down: nothing verifies
    assert not cold.verify(signed.key_id, b"x", signed.signature)


def test_unknown_key_ids_cannot_hammer_the_kms(emu: TransitEmulator) -> None:
    clock = [0.0]
    ring = KeyRing(loader=client(emu).public_keys, clock=lambda: clock[0])
    before = len(emu.requests)
    for i in range(20):
        assert not ring.verify(f"transit.{KEY}.v{90 + i}", b"x", "AAAA")
    assert len(emu.requests) == before
    clock[0] += 31
    ring.verify(f"transit.{KEY}.v99", b"x", "AAAA")
    assert len(emu.requests) == before + 1


@pytest.mark.parametrize(
    "doc",
    [
        {"data": {"type": "rsa-2048", "keys": {"1": {"public_key": "x"}}}},
        {"data": {"type": "ed25519", "keys": {}}},
        {"data": {"type": "ed25519", "keys": {"one": {"public_key": "AAAA"}}}},
        {"data": {"type": "ed25519", "keys": {"1": {"public_key": "not base64!"}}}},
        {"data": "nope"},
    ],
)
def test_malformed_key_descriptions_are_refused(doc: dict[str, Any]) -> None:
    c = TransitClient("http://127.0.0.1:1", KEY, "t", env=Environment.TEST,
                      fetch=lambda _: json.dumps(doc).encode())  # fmt: skip
    with pytest.raises(SigningError):
        c.public_keys()


@pytest.mark.parametrize(
    "sig",
    [
        "vault:v0:AAAAAAAAAAAAAAAAAAAAAAAA",
        "v1:AAAA",
        "vault:v1:",
        "vault:vX:AAAAAAAAAAAAAAAAAAAAAAAAAA",
        7,
    ],
)
def test_malformed_signatures_are_refused(sig: object) -> None:
    def fetch(_: urllib.request.Request) -> bytes:
        return json.dumps({"data": {"signature": sig}}).encode()

    with pytest.raises(SigningError, match="malformed"):
        TransitClient("http://127.0.0.1:1", KEY, "t", env=Environment.TEST, fetch=fetch).sign(b"x")


@pytest.mark.parametrize(
    ("addr", "env"),
    [
        ("http://kms.example.com:8200", Environment.TEST),
        ("http://127.0.0.1:8200", Environment.PROD),
        ("https://u:p@kms.example.com", Environment.PROD),
        ("https://kms.example.com/v1/transit", Environment.PROD),
    ],
)
def test_unsafe_kms_addresses_are_refused(addr: str, env: Environment) -> None:
    with pytest.raises(SigningError):
        TransitClient(addr, KEY, "t", env=env)


def test_names_are_simple_identifiers() -> None:
    for key, mount in (("../sys", "transit"), (KEY, "transit/../sys"), ("a b", "transit")):
        with pytest.raises(SigningError, match="identifiers"):
            TransitClient("https://kms.example.com", key, "t", mount=mount)


def test_token_file_must_be_private_and_well_formed(tmp_path: Path) -> None:
    assert read_token_file(token_file(tmp_path, "s.abc")) == "s.abc"
    with pytest.raises(SigningError, match="group/world"):
        read_token_file(token_file(tmp_path, "s.abc", 0o644))
    with pytest.raises(SigningError, match="malformed"):
        read_token_file(token_file(tmp_path, "two words"))
    with pytest.raises(SigningError, match="missing"):
        read_token_file(tmp_path / "absent")


def test_settings_wire_the_transit_backend(emu: TransitEmulator, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires kms_addr"):
        Settings(env="test", signing_backend="transit")
    with pytest.raises(ValueError, match="https"):
        Settings(env="prod", signing_backend="transit", kms_addr=emu.addr, kms_key=KEY,
                 kms_token_file=tmp_path / "t")  # fmt: skip
    s = Settings(env="test", signing_backend="transit", kms_addr=emu.addr, kms_key=KEY,
                 kms_token_file=token_file(tmp_path, emu.app_token),
                 signing_revoked_key_ids=" transit.old.v1 ,transit.old.v2")  # fmt: skip
    assert s.revoked_signing_keys == ["transit.old.v1", "transit.old.v2"]
    signer, ring = transit_from_settings(s)
    signed = signer.sign_detached(b"x")
    assert ring.verify(signed.key_id, b"x", signed.signature)


def test_local_signer_still_satisfies_the_protocol() -> None:
    s = LocalKeySigner.generate("local-1")
    signed = s.sign_detached(b"x")
    assert signed.key_id == "local-1" and KeyRing.from_signer(s).verify(
        "local-1", b"x", signed.signature
    )


# ---- the drill ----------------------------------------------------------------------------------
def test_full_rotation_drill_passes_on_the_emulator(emu: TransitEmulator) -> None:
    steps = run_drill(client(emu, emu.admin_token), rotate=True)
    names = [s.name for s in steps]
    assert passed(steps), [s for s in steps if not s.passed]
    assert {"old_signature_still_verifies", "retired_version_cannot_sign",
            "old_signature_verifies_after_retirement", "revoked_key_fails_closed"} <= set(names)  # fmt: skip
    md = render_markdown(report(steps, target="emu", key=KEY, rotate=True))
    assert "**PASS**" in md and "retired_version_cannot_sign" in md


def test_read_only_drill_does_not_change_the_key(emu: TransitEmulator) -> None:
    steps = run_drill(client(emu), rotate=False)
    assert passed(steps) and emu.keys[KEY].latest == 1
    assert "rotated" not in {s.name for s in steps}


def test_drill_fails_when_rotation_is_not_permitted_or_kms_is_down(emu: TransitEmulator) -> None:
    steps = run_drill(client(emu), rotate=True)  # the app token cannot rotate
    assert not passed(steps) and steps[-1].name == "rotated" and not steps[-1].passed
    emu.down = True
    down = run_drill(client(emu), rotate=False)
    assert [s.name for s in down] == ["kms_reachable"] and not passed(down)
