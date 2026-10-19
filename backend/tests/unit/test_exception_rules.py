"""When an exception covers an observation, and its displayed state (ADR-033)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisw.policy.exceptions import Grant, effect_at, state

T0 = datetime(2026, 10, 1, tzinfo=UTC)
DAY = timedelta(days=1)


def g(i: str = "e1", start: int = 0, days: int = 30, revoked: int | None = None) -> Grant:
    return Grant(i, T0 + start * DAY, T0 + (start + days) * DAY,
                 None if revoked is None else T0 + revoked * DAY)  # fmt: skip


@pytest.mark.parametrize(
    ("grant", "day", "expected"),
    [
        (g(), 0, "APPLIED"),  # approved at the moment of observation
        (g(), 29, "APPLIED"),
        (g(), 30, "EXPIRED"),  # expiry is exclusive
        (g(), 400, "EXPIRED"),
        (g(start=5), 4, None),  # observed before approval: never retroactive
        (g(revoked=10), 9, "APPLIED"),
        (g(revoked=10), 10, None),  # revoked: the finding is simply reported again
        (g(revoked=10), 45, None),
        (g(revoked=40), 35, "EXPIRED"),  # revoked after it had already lapsed
    ],
)  # fmt: skip
def test_effect_at(grant: Grant, day: int, expected: str | None) -> None:
    hit = effect_at([grant], T0 + day * DAY)
    assert (hit[1] if hit else None) == expected


def test_an_active_exception_wins_over_a_lapsed_one_and_ties_are_deterministic() -> None:
    old, new = g("e-old", start=0, days=10), g("e-new", start=20, days=30)
    hit = effect_at([old, new], T0 + 25 * DAY)
    assert hit is not None and hit == (new, "APPLIED")
    lapsed = effect_at([g("a", days=5), g("b", days=8)], T0 + 9 * DAY)
    assert lapsed is not None and lapsed[0].exception_id == "b"
    assert effect_at([], T0) is None


def test_state() -> None:
    exp = T0 + DAY
    assert state("REQUESTED", exp, T0) == "PENDING"
    assert state("APPROVED", exp, T0) == "ACTIVE"
    assert state("APPROVED", exp, exp) == "EXPIRED"
    assert state("REJECTED", exp, T0) == "REJECTED" and state("REVOKED", exp, T0) == "REVOKED"
    with pytest.raises(ValueError, match="unknown"):
        state("WHATEVER", exp, T0)
