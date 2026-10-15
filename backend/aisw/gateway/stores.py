"""Authorization state the gateway re-reads on EVERY dispatch (no caching of revocation)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import Engine, text

from aisw.authz.service import row_to_manifest, row_to_permit
from aisw.contracts.base import canonical_hash
from aisw.contracts.manifest import ExecutionPermit, ScopeManifest
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection


@dataclass(frozen=True)
class LoadedAuthorization:
    permit: ExecutionPermit
    revoked: bool
    manifest: ScopeManifest


class AuthorizationStore(Protocol):
    def load(self, tenant_id: str, permit_id: str) -> LoadedAuthorization | None: ...


class AuditSink(Protocol):
    def record(
        self, tenant_id: str, action: str, resource: str, result: str, reasons: list[str]
    ) -> None: ...


class DbAuthorizationStore:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def load(self, tenant_id: str, permit_id: str) -> LoadedAuthorization | None:
        with tenant_connection(self.engine, tenant_id) as conn:
            try:
                p = (
                    conn.execute(
                        text("SELECT * FROM execution_permits WHERE permit_id=:p"),
                        {"p": permit_id},
                    )
                    .mappings()
                    .first()
                )
            except Exception:  # malformed id etc.: treat as not found, fail closed
                return None
            if p is None:
                return None
            m = (
                conn.execute(
                    text("SELECT * FROM scope_manifests WHERE manifest_id=:m"),
                    {"m": str(p["manifest_id"])},
                )
                .mappings()
                .first()
            )
            if m is None:
                return None
            return LoadedAuthorization(
                row_to_permit(p), p["revoked_at"] is not None, row_to_manifest(m)
            )


class DbAuditSink:
    """Writes gateway decisions to the tenant's hash-chained audit trail."""

    def __init__(self, engine: Engine, service_actor: str = "tool-gateway") -> None:
        self.engine = engine
        self.actor = service_actor

    def record(
        self, tenant_id: str, action: str, resource: str, result: str, reasons: list[str]
    ) -> None:
        with tenant_connection(self.engine, tenant_id) as conn:
            append_audit(
                conn, tenant_id=tenant_id, actor=self.actor, action=action, resource=resource,
                result="SUCCESS" if result == "SUCCESS" else "DENIED",
                correlation_id="gateway", after_hash=canonical_hash({"reasons": reasons}),
            )  # fmt: skip


class MemoryAuthorizationStore:
    """Test double with the same semantics as the DB store."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], LoadedAuthorization] = {}

    def put(self, auth: LoadedAuthorization) -> None:
        self._items[(auth.permit.tenant_id, auth.permit.permit_id)] = auth

    def revoke(self, tenant_id: str, permit_id: str) -> None:
        cur = self._items[(tenant_id, permit_id)]
        self._items[(tenant_id, permit_id)] = LoadedAuthorization(cur.permit, True, cur.manifest)

    def load(self, tenant_id: str, permit_id: str) -> LoadedAuthorization | None:
        return self._items.get((tenant_id, permit_id))  # tenant is part of the key


class MemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str, str, list[str]]] = []

    def record(
        self, tenant_id: str, action: str, resource: str, result: str, reasons: list[str]
    ) -> None:
        self.events.append((tenant_id, action, resource, result, reasons))
