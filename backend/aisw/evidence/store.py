"""Content-addressed, tenant-partitioned evidence store on the local filesystem (SeaweedFS later).

Files are named by their sha256 and written exactly once (O_EXCL), so evidence is immutable by
construction; reads re-hash and fail loudly on any mismatch (bit-rot or tampering).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HASH = re.compile(r"^sha256:([0-9a-f]{64})$")


class EvidenceIntegrityError(Exception):
    pass


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, tenant_id: str, content_hash: str) -> Path:
        m = _HASH.match(content_hash)
        if not _TENANT.match(tenant_id) or not m:
            raise EvidenceIntegrityError("invalid tenant or hash")
        hexd = m.group(1)
        return self.root / tenant_id / hexd[:2] / hexd

    def put(self, tenant_id: str, data: bytes) -> str:
        content_hash = "sha256:" + hashlib.sha256(data).hexdigest()
        path = self._path(tenant_id, content_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        except FileExistsError:
            if path.read_bytes() != data:  # same name, different bytes: corruption/tampering
                raise EvidenceIntegrityError(
                    "existing evidence differs from content hash"
                ) from None
            return content_hash
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return content_hash

    def get(self, tenant_id: str, content_hash: str) -> bytes:
        path = self._path(tenant_id, content_hash)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError("evidence file missing") from exc
        if "sha256:" + hashlib.sha256(data).hexdigest() != content_hash:
            raise EvidenceIntegrityError("evidence hash mismatch")
        return data

    def verify(self, tenant_id: str, content_hash: str) -> bool:
        try:
            self.get(tenant_id, content_hash)
        except EvidenceIntegrityError:
            return False
        return True

    def quarantine(self, tenant_id: str, content_hash: str) -> bool:
        """Move a blob out of the live store (retention). Nothing is deleted: an operator removes
        quarantined files by hand, under their own change control. False if there was nothing to move."""
        path = self._path(tenant_id, content_hash)
        if not path.exists():
            return False
        dest = self.root / ".quarantine" / tenant_id / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():  # already quarantined once (restored and purged again): keep both
            dest = dest.with_name(f"{path.name}.{int(path.stat().st_mtime_ns)}")
        os.rename(path, dest)
        return True
