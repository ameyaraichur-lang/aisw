"""Scope-manifest signing (Ed25519). Production custody: a Transit-compatible KMS (ADR-027).

The signed payload binds tenant, project, manifest id, version and the canonical body hash, so a
valid signature cannot be lifted onto another tenant's or another version's manifest.
Private keys are never kept in settings, repo or logs; ``LocalKeySigner`` reads a key file whose
path is supplied by configuration and refuses group/world-readable key files.
"""

from __future__ import annotations

import base64
import os
import stat
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
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


@dataclass(frozen=True)
class Signed:
    """A signature together with the key that made it: never read the key id separately, since
    a rotation between the two reads would record the wrong key."""

    key_id: str
    signature: str


class ManifestSigner(Protocol):
    def sign_detached(self, payload: bytes) -> Signed: ...


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

    def sign_detached(self, payload: bytes) -> Signed:
        return Signed(self.key_id, self.sign(payload))

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()


KeyLoader = Callable[[], dict[str, Ed25519PublicKey]]
REFRESH_MIN_SECONDS = 30.0


class KeyRing:
    """Trusted public keys by id. Unknown and revoked key ids never verify (fail closed).

    With a ``loader`` (the KMS's published public keys), an unknown key id triggers one reload,
    at most every ``REFRESH_MIN_SECONDS``, so a rotation is picked up without a restart while
    garbage key ids cannot drive traffic to the KMS.
    """

    def __init__(
        self, *, revoked: Iterable[str] = (), loader: KeyLoader | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:  # fmt: skip
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._revoked = frozenset(revoked)
        self._loader = loader
        self._clock = clock
        self._loaded_at: float | None = None
        self._lock = threading.Lock()
        self._maybe_refresh()  # a KMS that is down at startup only means nothing verifies yet

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        self._keys[key_id] = public_key

    def key_ids(self) -> list[str]:
        return sorted(k for k in self._keys if k not in self._revoked)

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

    def refresh(self) -> None:
        if self._loader is None:
            return
        keys = self._loader()
        with self._lock:
            self._keys.update(keys)
            self._loaded_at = self._clock()

    def _maybe_refresh(self) -> None:
        with self._lock:
            due = self._loaded_at is None or self._clock() - self._loaded_at >= REFRESH_MIN_SECONDS
        if self._loader is not None and due:
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - an unreachable KMS just means "unknown key"
                with self._lock:
                    self._loaded_at = self._clock()

    @classmethod
    def from_signer(cls, signer: LocalKeySigner) -> KeyRing:
        ring = cls()
        ring.add(signer.key_id, signer.public_key())
        return ring

    def verify(self, key_id: str, payload: bytes, signature: str) -> bool:
        if key_id in self._revoked:
            return False
        key = self._keys.get(key_id)
        if key is None:
            self._maybe_refresh()
            key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(base64.b64decode(signature, validate=True), payload)
        except (InvalidSignature, ValueError):
            return False
        return True
