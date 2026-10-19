"""Manifest signing through a Transit-compatible KMS (OpenBao / Vault Transit API), ADR-027.

The private key never leaves the KMS: AISW asks it to sign and reads the published public keys
(one per key version). Verification stays local, through ``KeyRing``, so approved manifests keep
verifying while the KMS is unreachable. Key ids are ``transit.<key>.v<version>`` (they fit the manifest's ``key_id`` contract).

Rotation is a KMS operation (new version becomes the signing version); retiring a version is
``min_encryption_version`` (the KMS refuses to sign with older versions); trimming a version
destroys it, so never trim a version that an approved, unexpired manifest still references.
"""

from __future__ import annotations

import base64
import json
import re
import stat
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aisw.authz.signing import KeyRing, Signed, SigningError
from aisw.core import safe_http
from aisw.core.config import Environment, Settings, kms_url_problem

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,47}$")  # transit.<key>.v<n> stays within 64
_SIG = re.compile(r"^vault:v([1-9][0-9]{0,8}):([A-Za-z0-9+/=]{20,200})$")
MAX_VERSIONS = 1000

Fetch = Callable[[urllib.request.Request], bytes]


def transit_key_id(key: str, version: int) -> str:
    return f"transit.{key}.v{version}"


def read_token_file(path: Path) -> str:
    """The KMS token lives in a file the secret provider writes, readable by the service only."""
    if not path.is_file():
        raise SigningError("kms token file is missing")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SigningError("kms token file must not be group/world accessible")
    token = path.read_text().strip()
    if not token or len(token) > 4096 or any(c.isspace() for c in token):
        raise SigningError("kms token file is empty or malformed")
    return token


class TransitClient:
    def __init__(
        self, addr: str, key: str, token: str, *, mount: str = "transit",
        namespace: str | None = None, env: Environment = Environment.PROD,
        fetch: Fetch | None = None, timeout: float = 10,
    ) -> None:  # fmt: skip
        if problem := kms_url_problem(addr, env):
            raise SigningError(problem)
        if not (_KEY.match(key) and _NAME.match(mount)):
            raise SigningError("kms key and mount names must be simple identifiers")
        self._base = f"{addr.rstrip('/')}/v1/{quote(mount)}"
        self.key = key
        self._token = token
        self._namespace = namespace
        self._timeout = timeout
        self._fetch = fetch or (lambda req: safe_http.fetch(req, timeout=self._timeout))

    def __repr__(self) -> str:  # never the token
        return f"TransitClient(base={self._base!r}, key={self.key!r})"

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"X-Vault-Token": self._token, "Accept": "application/json"}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(  # noqa: S310 - origin validated in __init__
            f"{self._base}/{path}", data=data, headers=headers, method=method
        )
        try:
            raw = self._fetch(req)
        except safe_http.HttpError as exc:
            raise SigningError(f"kms {method} {path.split('/')[0]}: {exc}") from None
        if not raw:
            return {}
        try:
            doc = json.loads(raw)
        except ValueError:
            raise SigningError("kms answered non-JSON") from None
        if not isinstance(doc, dict):
            raise SigningError("kms answered non-object")
        return doc

    # ---- reads -----------------------------------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        data = self._call("GET", f"keys/{quote(self.key)}").get("data")
        if not isinstance(data, dict):
            raise SigningError("kms key description is malformed")
        if data.get("type") != "ed25519":
            raise SigningError("kms key must be ed25519")
        return data

    def public_keys(self) -> dict[str, Ed25519PublicKey]:
        data = self.describe()
        versions = data.get("keys")
        if not isinstance(versions, dict) or not 0 < len(versions) <= MAX_VERSIONS:
            raise SigningError("kms key has no usable versions")
        out: dict[str, Ed25519PublicKey] = {}
        for ver, info in versions.items():
            pub = info.get("public_key") if isinstance(info, dict) else None
            if not (str(ver).isdigit() and isinstance(pub, str)):
                raise SigningError("kms key version is malformed")
            try:
                key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub, validate=True))
            except ValueError:
                raise SigningError("kms public key is malformed") from None
            out[transit_key_id(self.key, int(ver))] = key
        return out

    # ---- signing ---------------------------------------------------------------------------------
    def sign(self, payload: bytes, *, version: int | None = None) -> Signed:
        body: dict[str, Any] = {"input": base64.b64encode(payload).decode()}
        if version is not None:
            body["key_version"] = version
        data = self._call("POST", f"sign/{quote(self.key)}", body).get("data")
        sig = data.get("signature") if isinstance(data, dict) else None
        m = _SIG.match(sig) if isinstance(sig, str) else None
        if m is None:
            raise SigningError("kms signature is malformed")
        return Signed(transit_key_id(self.key, int(m.group(1))), m.group(2))

    # ---- administration (rotation drill and operators; the app token must not have these) -------
    def rotate(self) -> int:
        self._call("POST", f"keys/{quote(self.key)}/rotate", {})
        return int(self.describe()["latest_version"])

    def retire_below(self, version: int) -> None:
        """Refuse signing with versions older than ``version``; they still verify."""
        self._call("POST", f"keys/{quote(self.key)}/config", {"min_encryption_version": version})


class TransitSigner:
    """``ManifestSigner`` backed by the KMS. A signature is only accepted if it verifies locally
    against the trusted key ring, so a revoked or unknown key version can never sign a manifest."""

    def __init__(self, client: TransitClient, keyring: KeyRing) -> None:
        self._client = client
        self._ring = keyring

    def sign_detached(self, payload: bytes) -> Signed:
        signed = self._client.sign(payload)
        if self._ring.is_revoked(signed.key_id):
            raise SigningError("kms signed with a revoked key version")
        if not self._ring.verify(signed.key_id, payload, signed.signature):
            self._ring.refresh()  # a just-rotated version: one forced reload
            if not self._ring.verify(signed.key_id, payload, signed.signature):
                raise SigningError("kms signature does not verify against the trusted keys")
        return signed


def transit_from_settings(
    settings: Settings, *, fetch: Fetch | None = None
) -> tuple[TransitSigner, KeyRing]:
    if not (settings.kms_addr and settings.kms_key and settings.kms_token_file):
        raise SigningError("transit signing needs kms_addr, kms_key and kms_token_file")
    client = TransitClient(
        settings.kms_addr, settings.kms_key, read_token_file(settings.kms_token_file),
        mount=settings.kms_mount, namespace=settings.kms_namespace, env=settings.env, fetch=fetch,
    )  # fmt: skip
    ring = KeyRing(revoked=settings.revoked_signing_keys, loader=client.public_keys)
    return TransitSigner(client, ring), ring
