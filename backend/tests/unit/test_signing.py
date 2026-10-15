from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from aisw.authz.signing import KeyRing, LocalKeySigner, SigningError, signing_payload

P: dict[str, Any] = {
    "tenant_id": "t",
    "project_id": "p",
    "manifest_id": "m",
    "version": 1,
    "canonical_hash": "sha256:" + "a" * 64,
}


def test_sign_verify_roundtrip_and_binding() -> None:
    s = LocalKeySigner.generate("k1")
    ring = KeyRing.from_signer(s)
    sig = s.sign(signing_payload(**P))
    assert ring.verify("k1", signing_payload(**P), sig)
    for field, value in (("tenant_id", "t2"), ("project_id", "p2"), ("manifest_id", "m2"),
                         ("version", 2), ("canonical_hash", "sha256:" + "b" * 64)):  # fmt: skip
        assert not ring.verify("k1", signing_payload(**{**P, field: value}), sig)


@pytest.mark.parametrize("sig", ["", "not-base64!!", "AAAA", "A" * 200])
def test_garbage_signatures_never_verify(sig: str) -> None:
    s = LocalKeySigner.generate("k1")
    assert not KeyRing.from_signer(s).verify("k1", b"payload", sig)


def test_unknown_key_id_and_wrong_key_fail_closed() -> None:
    a, b = LocalKeySigner.generate("k1"), LocalKeySigner.generate("k1")
    sig = a.sign(b"x")
    assert not KeyRing().verify("k1", b"x", sig)
    assert not KeyRing.from_signer(b).verify("k1", b"x", sig)
    assert not KeyRing.from_signer(a).verify("other", b"x", sig)


def test_key_file_is_private_and_reloadable(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "signing.pem"
    s1 = LocalKeySigner.load_or_create("k1", path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    s2 = LocalKeySigner.load_or_create("k1", path)
    assert KeyRing.from_signer(s1).verify("k1", b"x", s2.sign(b"x"))  # same key reloaded
    os.chmod(path, 0o644)
    with pytest.raises(SigningError):
        LocalKeySigner.load_or_create("k1", path)
