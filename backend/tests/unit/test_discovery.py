from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisw.agents.discovery import (
    CmdbRow,
    KnownAsset,
    known_value,
    norm_host,
    reconcile_cmdb,
    resolve_identity,
)

NOW = datetime(2026, 10, 15, tzinfo=UTC)


def row(
    i: str,
    host: str | None = None,
    ip: str | None = None,
    owner: str | None = "team",
    crit: str | None = "high",
    seen: datetime | None = NOW - timedelta(days=1),
) -> CmdbRow:
    return CmdbRow(i, host, ip, "linux", owner, crit, "prod", seen, "cmdb")


@pytest.mark.parametrize(
    "v", [None, "", " ", "TBD", "tbd", "Unknown", "N/A", "none", "-", "?", "Unassigned"]
)
def test_placeholders_are_unknown(v: str | None) -> None:
    assert known_value(v) is None


def test_real_values_survive_and_hosts_normalize() -> None:
    assert (
        known_value("  team-web ") == "team-web"
        and norm_host("Web-01.Corp.Test.") == "web-01.corp.test"
        and norm_host("") is None
    )


def test_reconcile_names_unknown_owner_stale_and_missing_dates() -> None:
    rec = reconcile_cmdb(
        [
            row("a", owner="TBD"),
            row("b", seen=NOW - timedelta(days=200)),
            row("c", seen=None),
            row("d"),
        ],
        now=NOW,
        stale_after=timedelta(days=90),
    )
    kinds = {(g.kind, g.subject) for g in rec.gaps}
    assert kinds == {("OWNER_UNKNOWN", "a"), ("STALE_RECORD", "b"), ("STALE_RECORD", "c")}
    flags = {a.row.asset_id: a.flags for a in rec.assets}
    assert "NO_LAST_SEEN" in flags["c"] and flags["d"] == () and rec.assets[0].owner is None


def test_possible_duplicates_by_ip_or_hostname_are_flagged_not_merged() -> None:
    rec = reconcile_cmdb(
        [
            row("a", "web.x", "10.0.0.1"),
            row("b", "WEB.x.", "10.0.0.2"),
            row("c", "other", "10.0.0.1"),
        ],
        now=NOW,
        stale_after=timedelta(days=90),
    )
    dups = [g for g in rec.gaps if g.kind == "DUPLICATE_CANDIDATE"]
    assert {g.subject for g in dups} == {"a,b", "a,c"}
    assert [a.row.asset_id for a in rec.assets] == [
        "a",
        "b",
        "c",
    ]  # nothing merged, nothing dropped
    assert all("DUPLICATE_CANDIDATE" in a.flags for a in rec.assets)


def test_the_same_id_with_different_identity_is_a_conflict_and_is_not_trusted() -> None:
    rec = reconcile_cmdb(
        [row("a", "h1", "10.0.0.1"), row("a", "h2", "10.0.0.2"), row("b")],
        now=NOW,
        stale_after=timedelta(days=90),
    )
    assert [g.kind for g in rec.gaps] == ["CONFLICTING_RECORDS"] and [
        a.row.asset_id for a in rec.assets
    ] == ["b"]
    same = reconcile_cmdb(
        [row("a", "h1", "10.0.0.1"), row("a", "h1", "10.0.0.1")],
        now=NOW,
        stale_after=timedelta(days=90),
    )
    assert [a.row.asset_id for a in same.assets] == [
        "a"
    ] and same.gaps == []  # an exact repeat is harmless


KNOWN = [KnownAsset("host-1", "10.0.0.1", "web-01.corp.test"), KnownAsset("host-2", "10.0.0.2", "db-01.corp.test"), KnownAsset("host-3", None, "win-01.corp.test"),
         KnownAsset("host-4", "10.0.0.4", "app.east.corp.test"), KnownAsset("host-5", "10.0.0.5", "app.west.corp.test")]  # fmt: skip


@pytest.mark.parametrize(
    ("ip", "host", "status", "asset", "conf"),
    [
        (
            "10.0.0.1",
            "WEB-01.corp.test.",
            "MATCHED",
            "host-1",
            "HIGH",
        ),  # ip and hostname agree (case/dot-insensitive)
        ("10.0.0.1", None, "MATCHED", "host-1", "MEDIUM"),
        (None, "db-01.corp.test", "MATCHED", "host-2", "MEDIUM"),
        (
            "10.0.0.99",
            "win-01.corp.test",
            "MATCHED",
            "host-3",
            "MEDIUM",
        ),  # a changed IP still matches the hostname
        (None, "web-01", "MATCHED", "host-1", "MEDIUM"),  # short name identifying exactly one asset
        ("10.0.0.1", "db-01.corp.test", "AMBIGUOUS", None, "LOW"),  # ip and hostname disagree
        (None, "app", "AMBIGUOUS", None, "LOW"),  # short name matching two assets is not guessed
        ("10.0.0.77", "ghost.corp.test", "NEW", None, "LOW"),
        (None, None, "NEW", None, "LOW"),
    ],
)
def test_identity_resolution_rules(
    ip: str | None, host: str | None, status: str, asset: str | None, conf: str
) -> None:
    r = resolve_identity(KNOWN, ip=ip, hostname=host)
    assert (r.status, r.asset_id, r.confidence) == (status, asset, conf)


def test_duplicate_known_identities_are_ambiguous() -> None:
    twin = [*KNOWN, KnownAsset("host-9", "10.0.0.1", "web-01.corp.test")]
    assert resolve_identity(twin, ip="10.0.0.1", hostname="web-01.corp.test").status == "AMBIGUOUS"
    assert resolve_identity(twin, ip="10.0.0.1", hostname=None).status == "AMBIGUOUS"
