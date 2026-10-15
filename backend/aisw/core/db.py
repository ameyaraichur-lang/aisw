"""Database access: every tenant-scoped query runs inside a transaction that sets app.tenant_id.

The application connects as a role that is neither owner nor BYPASSRLS; row-level security is
the backstop even if application code forgets a tenant filter.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Connection, Engine, create_engine, text


def make_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, future=True)


@contextmanager
def tenant_connection(engine: Engine, tenant_id: str) -> Iterator[Connection]:
    """Open a transaction scoped to one tenant (set_config is transaction-local)."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant_id})
        yield conn
