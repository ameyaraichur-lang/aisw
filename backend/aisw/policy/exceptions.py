"""When an approved exception covers a failing observation (ADR-033). Pure and deterministic.

An exception applies to an observation made while it was in force: approved at or before the
observation, not yet expired, and not revoked by then. Once expired it no longer hides anything, and
the run says so instead of silently reporting the finding as new.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

Effect = Literal["APPLIED", "EXPIRED"]
State = Literal["PENDING", "ACTIVE", "EXPIRED", "REJECTED", "REVOKED"]


@dataclass(frozen=True)
class Grant:
    exception_id: str
    approved_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


def effect_at(grants: Iterable[Grant], t: datetime) -> tuple[Grant, Effect] | None:
    gs = list(grants)
    active = [
        g for g in gs
        if g.approved_at <= t < g.expires_at and (g.revoked_at is None or t < g.revoked_at)
    ]  # fmt: skip
    if active:
        return max(active, key=lambda g: (g.expires_at, g.exception_id)), "APPLIED"
    lapsed = [
        g
        for g in gs
        if g.expires_at <= t and (g.revoked_at is None or g.revoked_at >= g.expires_at)
    ]
    if lapsed:
        return max(lapsed, key=lambda g: (g.expires_at, g.exception_id)), "EXPIRED"
    return None


def state(status: str, expires_at: datetime, now: datetime) -> State:
    if status == "REQUESTED":
        return "PENDING"
    if status == "APPROVED":
        return "ACTIVE" if now < expires_at else "EXPIRED"
    if status in ("REJECTED", "REVOKED"):
        return status  # type: ignore[return-value]
    raise ValueError(f"unknown exception status {status}")


__all__ = ["Effect", "Grant", "State", "effect_at", "state"]
