"""Write-once replica of the evidence store (ADR-042).

Every blob written to the live store is also written to an object-lock backend in COMPLIANCE mode
with a retain-until date, so neither the platform nor an administrator can alter or remove it
before then. The live store stays the read path; the replica is checked by ``verify`` and used by
an operator to restore a missing or damaged live copy, never to bring back a quarantined one.

``LocalObjectLockEmulator`` reproduces the S3 Object Lock rules on a filesystem for development and
tests. A real bucket (S3, MinIO or Ceph with Object Lock) needs the ``evidence-worm-storage``
sign-off; until then production has no replica and the doctor says so.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from aisw.evidence.store import _HASH, _TENANT, EvidenceIntegrityError, EvidenceStore

Mode = Literal["COMPLIANCE"]
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[0-9a-f]{64}$")


class ObjectLocked(Exception):
    """The object is under retention: it cannot be overwritten, shortened or deleted yet."""


@dataclass(frozen=True)
class LockInfo:
    mode: Mode
    retain_until: datetime


class ObjectLockBackend(Protocol):
    backend_id: str

    def put(self, key: str, data: bytes, retain_until: datetime) -> None: ...
    def get(self, key: str) -> bytes: ...
    def lock(self, key: str) -> LockInfo | None: ...
    def extend(self, key: str, retain_until: datetime) -> None: ...
    def delete(self, key: str) -> None: ...


class LocalObjectLockEmulator:
    """Object Lock COMPLIANCE semantics on a directory (dev/test only, not tamper-proof)."""

    backend_id = "local-object-lock-emulator"

    def __init__(self, root: Path, clock: Callable[[], datetime] | None = None) -> None:
        self.root = root
        self._clock = clock or (lambda: datetime.now(UTC))

    def _paths(self, key: str) -> tuple[Path, Path]:
        if not _KEY.match(key):
            raise ObjectLocked("invalid object key")
        data = self.root / key
        return data, data.with_name(data.name + ".lock.json")

    def lock(self, key: str) -> LockInfo | None:
        _, meta = self._paths(key)
        if not meta.exists():
            return None
        m = json.loads(meta.read_text())
        return LockInfo(m["mode"], datetime.fromisoformat(m["retain_until"]))

    def _write_lock(self, meta: Path, retain_until: datetime) -> None:
        tmp = meta.with_name(meta.name + ".tmp")
        tmp.write_text(
            json.dumps(
                {"mode": "COMPLIANCE", "retain_until": retain_until.astimezone(UTC).isoformat()}
            )
        )
        os.replace(tmp, meta)

    def put(self, key: str, data: bytes, retain_until: datetime) -> None:
        path, meta = self._paths(key)
        if path.exists():
            if path.read_bytes() != data:
                raise ObjectLocked("an object with this key holds different content")
            current = self.lock(key)
            if current is None or retain_until > current.retain_until:
                self._write_lock(meta, retain_until)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self._write_lock(meta, retain_until)

    def get(self, key: str) -> bytes:
        path, _ = self._paths(key)
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError("replica object missing") from exc

    def extend(self, key: str, retain_until: datetime) -> None:
        _, meta = self._paths(key)
        current = self.lock(key)
        if current is None:
            raise EvidenceIntegrityError("replica object missing")
        if retain_until < current.retain_until:
            raise ObjectLocked("COMPLIANCE retention can only be extended")
        self._write_lock(meta, retain_until)

    def delete(self, key: str) -> None:
        path, meta = self._paths(key)
        current = self.lock(key)
        if current is not None and self._clock() < current.retain_until:
            raise ObjectLocked(f"retained until {current.retain_until.isoformat()}")
        path.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)


class WormEvidenceStore(EvidenceStore):
    """The live store plus a write-once replica; a write is complete only when both hold it."""

    def __init__(
        self,
        root: Path,
        replica: ObjectLockBackend,
        retain_days: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(root)
        self.replica = replica
        self.retain = timedelta(days=retain_days)
        self._clock = clock or (lambda: datetime.now(UTC))

    @staticmethod
    def key(tenant_id: str, content_hash: str) -> str:
        m = _HASH.match(content_hash)
        if not _TENANT.match(tenant_id) or not m:
            raise EvidenceIntegrityError("invalid tenant or hash")
        return f"{tenant_id}/{m.group(1)}"

    def put(self, tenant_id: str, data: bytes) -> str:
        content_hash = super().put(tenant_id, data)
        try:
            self.replica.put(self.key(tenant_id, content_hash), data, self._clock() + self.retain)
        except (ObjectLocked, OSError) as exc:
            raise EvidenceIntegrityError(f"write-once replica refused the object: {exc}") from exc
        return content_hash

    def replica_ok(self, tenant_id: str, content_hash: str) -> bool:
        try:
            data = self.replica.get(self.key(tenant_id, content_hash))
        except (EvidenceIntegrityError, OSError):
            return False
        return "sha256:" + hashlib.sha256(data).hexdigest() == content_hash

    def verify(self, tenant_id: str, content_hash: str) -> bool:
        return super().verify(tenant_id, content_hash) and self.replica_ok(tenant_id, content_hash)

    def lock(self, tenant_id: str, content_hash: str) -> LockInfo | None:
        return self.replica.lock(self.key(tenant_id, content_hash))

    def quarantined(self, tenant_id: str, content_hash: str) -> bool:
        name = self._path(tenant_id, content_hash).name
        q = self.root / ".quarantine" / tenant_id
        return q.exists() and any(p.name.split(".")[0] == name for p in q.iterdir())

    def restore(self, tenant_id: str, content_hash: str) -> bool:
        """Rewrite a missing or damaged live copy from the replica. Never undoes a retention purge."""
        if super().verify(tenant_id, content_hash) or self.quarantined(tenant_id, content_hash):
            return False
        if not self.replica_ok(tenant_id, content_hash):
            raise EvidenceIntegrityError("replica copy is missing or does not match its hash")
        path = self._path(tenant_id, content_hash)
        path.unlink(missing_ok=True)
        super().put(tenant_id, self.replica.get(self.key(tenant_id, content_hash)))
        return True
