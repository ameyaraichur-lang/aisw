"""Scope-manifest signing (Ed25519). Production custody: OpenBao Transit (planned, M8).

The signed payload binds tenant, project, manifest id, version and the canonical body hash, so a
valid signature cannot be lifted onto another tenant's or another version's manifest.
Private keys are never kept in settings, repo or logs; ``LocalKeySigner`` reads a key file whose
path is supplied by configuration and refuses group/world-readable key files.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aisw.contracts.base import canonical_json

DOMAIN = "aisw-scope-manifest-v1"


class SigningError(Exception):
    pass


def signing_payload(
    *, tenant_id: str, project_id: str, manifest_id: str, version: int, canonical_hash: str
) -> bytes:
    return canonical_json(
        {
            "domain": DOMAIN,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "manifest_id": manifest_id,
            "version": version,
            "canonical_hash": canonical_hash,
        }
    )


class ManifestSigner(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...


class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: bytes, signature: str) -> bool: ...


class LocalKeySigner:
    """Dev/test signer. Not a substitute for HSM/Transit custody in production."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._key = private_key

    @classmethod
    def generate(cls, key_id: str) -> LocalKeySigner:
        return cls(key_id, Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, key_id: str, path: Path) -> LocalKeySigner:
        if path.exists():
            if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SigningError("signing key file must not be group/world accessible")
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise SigningError("signing key must be Ed25519")
            return cls(key_id, key)
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        return cls(key_id, key)

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._key.sign(payload)).decode("ascii")

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()


class KeyRing:
    """Trusted public keys by id. Unknown key ids never verify (fail closed)."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        self._keys[key_id] = public_key

    @classmethod
    def from_signer(cls, signer: LocalKeySigner) -> KeyRing:
        ring = cls()
        ring.add(signer.key_id, signer.public_key())
        return ring

    def verify(self, key_id: str, payload: bytes, signature: str) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(base64.b64decode(signature, validate=True), payload)
        except (InvalidSignature, ValueError):
            return False
        return True
