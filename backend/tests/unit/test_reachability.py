"""Reachability graph rules (ADR-041): what counts as an edge, and what is only a caveat."""

from __future__ import annotations

from typing import Any

import pytest

from aisw.agents import reachability as reach
from aisw.agents.correlation import build_path_scenarios
from aisw.contracts.analysis import INTERNET, RiskAssessment, RiskFactors
from aisw.contracts.enums import EdgeBasis
from tests.unit.analysis_support import finding

HOSTS = [reach.Host("web", "10.0.0.1", "web.test"), reach.Host("app", "10.0.0.2", "app.test"),
         reach.Host("db", "10.0.1.3", "db.test"), reach.Host("dmz", "192.0.2.10", None)]  # fmt: skip


def rule(host: str, sources: list[str], via: str = "r1", **fact: Any) -> reach.RuleFact:
    return reach.RuleFact(via, "rule", host, {"direction": "ingress", "action": "allow",
                                              "sources": sources, "protocol": "tcp", **fact}, "ev://fw")  # fmt: skip


def pairs(g: reach.Graph) -> dict[tuple[str, str], Any]:
    return {(e.src, e.dst): e for e in g.edges}


def test_any_source_public_range_and_private_range_edges() -> None:
    g = reach.build(HOSTS, [
        rule("10.0.0.1", ["0.0.0.0/0"], "r1", port_ranges=[[443, 443]]),
        rule("app.test", ["203.0.113.0/24"], "r2", port_ranges=[[8443, 8443]]),
        rule("db", ["10.0.0.0/24"], "r3", port_ranges=[[5432, 5432]]),
    ], [])  # fmt: skip
    e = pairs(g)
    assert e[INTERNET, "web"].ports == [(443, 443)] and e[INTERNET, "web"].note is None
    assert e[INTERNET, "app"].note == "only from 203.0.113.0/24"
    assert e["web", "db"].ports == [(5432, 5432)] and e["app", "db"].basis is EdgeBasis.CONFIGURED
    assert ("dmz", "db") not in e and (INTERNET, "db") not in e and ("dmz", "app") not in e
    assert g.caveats == ["UPSTREAM_FILTERING_NOT_EVALUATED"]


def test_icmp_deny_and_unresolvable_sources_add_nothing() -> None:
    g = reach.build(HOSTS, [
        rule("web", ["0.0.0.0/0"], "icmp", port_ranges=[]),
        reach.RuleFact("deny", "rule", "web", {"action": "deny", "sources": ["0.0.0.0/0"], "all_ports": True}, "ev"),
        rule("web", ["sg:sg-123", "pl:pl-9"], "sg-ref", all_ports=True),
        reach.RuleFact("pol", "policy", "web", {"default_action": "deny"}, "ev"),
    ], [])  # fmt: skip
    assert g.edges == [] and g.caveats == []


def test_default_allow_policy_opens_every_port_from_everywhere() -> None:
    g = reach.build(
        HOSTS, [reach.RuleFact("pol", "policy", "db", {"default_action": "allow"}, "ev")], []
    )
    e = pairs(g)
    assert (
        e[INTERNET, "db"].ports is None
        and e[INTERNET, "db"].note == "the INPUT chain accepts by default"
    )
    assert {s for s, d in e if d == "db"} == {INTERNET, "web", "app", "dmz"}


def test_unknown_or_ambiguous_firewall_hosts_and_security_groups_are_caveats() -> None:
    twins = [*HOSTS, reach.Host("web-b", "10.0.0.9", "web.test")]
    g = reach.build(twins, [
        rule("nowhere.test", ["0.0.0.0/0"], all_ports=True),
        rule("web.test", ["0.0.0.0/0"], all_ports=True),
        reach.RuleFact("sgr", "security_group_rule", None, {"sources": ["0.0.0.0/0"], "all_ports": True}, "ev"),
    ], [])  # fmt: skip
    assert g.edges == []
    assert g.caveats == ["AMBIGUOUS_FIREWALL_HOST:web.test", "SECURITY_GROUP_ATTACHMENTS_UNKNOWN:1",
                         "UNRESOLVED_FIREWALL_HOST:nowhere.test"]  # fmt: skip


def test_only_a_declared_untrusted_vantage_makes_open_ports_an_observed_exposure() -> None:
    scans = [
        reach.OpenPorts("10.0.0.1", None, [443, 22, 443], "untrusted", "nmap_import", "ev://a"),
        reach.OpenPorts("10.0.0.2", None, [22], None, "nmap_import", "ev://b"),
        reach.OpenPorts("10.0.1.3", None, [5432], "internal", "nmap_import", "ev://c"),
        reach.OpenPorts(None, "ghost.test", [80], "untrusted", "nmap_import", "ev://d"),
        reach.OpenPorts("10.0.0.1", None, [], "untrusted", "nmap_import", "ev://e"),
    ]
    g = reach.build(HOSTS, [], scans)
    assert [(e.src, e.dst, e.basis, e.ports) for e in g.edges] == [
        (INTERNET, "web", EdgeBasis.OBSERVED, [(22, 22), (443, 443)])
    ]
    assert g.caveats == ["SCAN_VANTAGE_NOT_STATED:1", "UNRESOLVED_SCANNED_HOST:ghost.test"]


def test_exposure_takes_the_strongest_level_and_only_its_edges() -> None:
    g = reach.build(HOSTS, [rule("web", ["0.0.0.0/0"], all_ports=True)],
                    [reach.OpenPorts("10.0.0.1", None, [443], "untrusted", "nmap_import", "ev")])  # fmt: skip
    observed = next(e for e in g.edges if e.basis is EdgeBasis.OBSERVED)
    assert reach.exposure(g.edges) == {"web": ("VERIFIED", [observed.edge_id])}


def test_paths_are_shortest_prefer_observed_hops_and_stop_at_the_hop_limit() -> None:
    chain = [reach.Host(f"h{i}", f"10.9.0.{i}", None) for i in range(1, 7)]
    rules = [rule(f"h{i + 1}", [f"10.9.0.{i}/32"], f"r{i}", all_ports=True) for i in range(1, 6)]
    rules.append(rule("h1", ["0.0.0.0/0"], "edge", all_ports=True))
    g = reach.build(
        chain, rules, [reach.OpenPorts("10.9.0.1", None, [443], "untrusted", "nmap_import", "ev")]
    )
    p = reach.paths(g.edges, ["h2", "h4", "h5", "h6"])
    assert [(e.src, e.dst) for e in p["h4"]] == [
        (INTERNET, "h1"),
        ("h1", "h2"),
        ("h2", "h3"),
        ("h3", "h4"),
    ]
    assert p["h2"][0].basis is EdgeBasis.OBSERVED
    assert "h5" not in p and "h6" not in p  # beyond MAX_HOPS
    assert reach.paths(g.edges, ["h6"], max_hops=6)["h6"][-1].dst == "h6"


def test_a_path_scenario_needs_only_one_finding_and_names_its_route() -> None:
    g = reach.build(HOSTS, [rule("web", ["0.0.0.0/0"], "r1", all_ports=True),
                            rule("db", ["10.0.0.1/32"], "r2", port_ranges=[[5432, 5432]])], [])  # fmt: skip
    f = finding("f1", asset="db")
    risk = RiskAssessment(finding_id="f1", rubric_version="1.0.0", tier=None, provisional_tier="P2",
                          basis="NEEDS_POLICY_REVIEW", rationale="x",
                          factors=RiskFactors(severity="HIGH", criticality=None, exposure="UNKNOWN",
                                              evidence_fresh=True, corroborating_sources=1))  # fmt: skip
    [s] = build_path_scenarios([f], {"f1": risk}, reach.paths(g.edges, ["db"]))
    assert (
        s.title
        == "db is reachable from the internet in 2 hops (internet → web → db) with 1 recorded weakness"
    )
    assert s.confidence.value == "LOW" and s.validation_steps[1].startswith(
        "Confirm with the network owner that web reaches db on 5432"
    )
    with pytest.raises(ValueError, match="two findings"):
        type(s).model_validate({**s.model_dump(mode="json"), "path": []})
