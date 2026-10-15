"""DB-backed inventory used by the scope gate to resolve targets (tenant-scoped via RLS)."""

from __future__ import annotations

from sqlalchemy import Engine, text

from aisw.core.db import tenant_connection


class DbInventory:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def resolve(self, tenant_id: str, project_id: str, kind: str, selector: str) -> str | None:
        with tenant_connection(self.engine, tenant_id) as conn:
            try:
                return conn.execute(
                    text(
                        "SELECT resolved_id FROM inventory_entries "
                        "WHERE project_id=:p AND kind=:k AND selector=:s"
                    ),
                    {"p": project_id, "k": kind, "s": selector},
                ).scalar()
            except Exception:  # malformed project id etc.: not resolvable, fail closed
                return None
