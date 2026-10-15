"""Evidence references: evidence://<tenant>/<project>/<run>/<path>."""

from __future__ import annotations

import re
from typing import NamedTuple

_REF = re.compile(
    r"^evidence://(?P<tenant>[A-Za-z0-9][A-Za-z0-9._-]{0,63})/"
    r"(?P<project>[A-Za-z0-9][A-Za-z0-9._-]{0,63})/"
    r"(?P<run>[A-Za-z0-9][A-Za-z0-9._-]{0,63})/"
    r"(?P<path>[A-Za-z0-9][A-Za-z0-9._/-]{0,255})$"
)


class RefError(ValueError):
    pass


class EvidenceRef(NamedTuple):
    tenant_id: str
    project_id: str
    run_id: str
    path: str

    @classmethod
    def parse(cls, raw: str) -> EvidenceRef:
        m = _REF.match(raw)
        if not m or ".." in m["path"].split("/") or "//" in m["path"]:
            raise RefError("malformed evidence reference")
        return cls(m["tenant"], m["project"], m["run"], m["path"])

    def __str__(self) -> str:
        return f"evidence://{self.tenant_id}/{self.project_id}/{self.run_id}/{self.path}"


def require_in_scope(raw_refs: list[str], *, tenant_id: str, project_id: str) -> list[EvidenceRef]:
    """Every reference must resolve inside the same tenant and project (Appendix G)."""
    out: list[EvidenceRef] = []
    for raw in raw_refs:
        ref = EvidenceRef.parse(raw)
        if ref.tenant_id != tenant_id or ref.project_id != project_id:
            raise RefError("evidence reference is outside the authorized tenant/project")
        out.append(ref)
    return out
