"""Idempotent command execution. The key record and the side effect share one transaction."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text

from aisw.contracts.base import canonical_hash


class IdempotencyConflict(Exception):
    """Same key reused with a different request body."""


@dataclass(frozen=True)
class IdempotentResult:
    status_code: int
    body: dict[str, Any]
    replayed: bool


def run_idempotent(
    conn: Connection,
    *,
    tenant_id: str,
    actor: str,
    scope: str,
    key: str,
    request_body: dict[str, Any],
    handler: Callable[[], tuple[int, dict[str, Any]]],
) -> IdempotentResult:
    req_hash = canonical_hash(request_body)
    params = {"t": tenant_id, "a": actor, "s": scope, "k": key, "h": req_hash}
    inserted = conn.execute(
        text(
            "INSERT INTO idempotency_records (tenant_id, actor, scope, idem_key, request_hash) "
            "VALUES (:t, :a, :s, :k, :h) ON CONFLICT DO NOTHING RETURNING 1"
        ),
        params,
    ).first()
    if inserted is None:
        row = conn.execute(
            text(
                "SELECT request_hash, status_code, response FROM idempotency_records "
                "WHERE tenant_id=:t AND actor=:a AND scope=:s AND idem_key=:k"
            ),
            params,
        ).first()
        if row is None or row[0] != req_hash:
            raise IdempotencyConflict("idempotency key reused with a different request")
        if row[1] is None:
            raise IdempotencyConflict("original request has not completed")
        return IdempotentResult(row[1], row[2], replayed=True)
    status, body = handler()
    conn.execute(
        text(
            "UPDATE idempotency_records SET status_code=:sc, response=CAST(:r AS jsonb) "
            "WHERE tenant_id=:t AND actor=:a AND scope=:s AND idem_key=:k"
        ),
        {**params, "sc": status, "r": json.dumps(body)},
    )
    return IdempotentResult(status, body, replayed=False)
