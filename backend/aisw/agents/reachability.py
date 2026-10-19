"""Reachability graph (ADR-041), deterministic: which hosts traffic can reach, and from where.

Edges come only from evidence already recorded in the run:

* CONFIGURED: a host firewall (iptables INPUT) rule or default policy that accepts traffic from
  any address, a public range, or the address of another host in the run;
* OBSERVED: open ports seen by a network scan whose launcher declared it was run from an untrusted
  network. A scan with no declared vantage proves nothing about the internet and adds no edge.

Nothing is sent and nothing is assumed: upstream filtering, NAT and cloud security groups whose
attachments are unknown are reported as caveats, not modelled.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from aisw.contracts.analysis import INTERNET, ReachEdge
from aisw.contracts.enums import EdgeBasis

MAX_HOPS = 4
Exposure = Literal["VERIFIED", "CONFIGURED", "UNKNOWN"]
RANK: dict[str, int] = {"UNKNOWN": 0, "CONFIGURED": 1, "VERIFIED": 2}


@dataclass(frozen=True)
class Host:
    asset_id: str
    ip: str | None
    hostname: str | None


@dataclass(frozen=True)
class RuleFact:
    """A firewall rule or policy observation; ``host`` is the selector the import was run for."""

    via: str
    kind: Literal["rule", "policy", "security_group_rule"]
    host: str | None
    fact: Mapping[str, Any]
    evidence_ref: str


@dataclass(frozen=True)
class OpenPorts:
    ip: str | None
    hostname: str | None
    ports: Sequence[int]
    vantage: str | None
    source: str
    evidence_ref: str


@dataclass
class Graph:
    edges: list[ReachEdge] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)


def edge_id(src: str, dst: str, via: str) -> str:
    return "re-" + hashlib.sha256(f"{src}|{dst}|{via}".encode()).hexdigest()[:16]


def _resolve(selector: str, hosts: Sequence[Host]) -> list[Host]:
    s = selector.lower()
    return [
        h
        for h in hosts
        if s in {h.asset_id.lower(), (h.ip or "").lower(), (h.hostname or "").lower()}
    ]


def _ports(fact: Mapping[str, Any]) -> list[tuple[int, int]] | None | Literal[False]:
    """None: every port; False: no TCP/UDP port (ICMP)."""
    if fact.get("all_ports"):
        return None
    ranges = fact.get("port_ranges")
    if not ranges:
        return False
    return [(int(lo), int(hi)) for lo, hi in ranges]


INTERNAL = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
              "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")
)  # fmt: skip


def _internal(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Only address space that cannot be routed from the internet counts as internal."""
    return any(net.version == n.version and net.subnet_of(n) for n in INTERNAL)  # type: ignore[arg-type]


def _inside(ip: str | None, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def build(hosts: Sequence[Host], rules: Iterable[RuleFact], scans: Iterable[OpenPorts]) -> Graph:
    g = Graph()
    seen: set[str] = set()
    caveats: set[str] = set()

    def add(src: str, dst: str, basis: EdgeBasis, ports: list[tuple[int, int]] | None,
            via: str, ref: str, note: str | None) -> None:  # fmt: skip
        eid = edge_id(src, dst, via)
        if eid in seen:
            return
        seen.add(eid)
        g.edges.append(ReachEdge(edge_id=eid, src=src, dst=dst, basis=basis, ports=ports,
                                 via=via, evidence_ref=ref, note=note))  # fmt: skip

    sg_rules = 0
    for r in rules:
        if r.kind == "security_group_rule":
            sg_rules += 1
            continue
        if not r.host:
            continue
        match = _resolve(r.host, hosts)
        if len(match) != 1:
            caveats.add(f"{'AMBIGUOUS' if match else 'UNRESOLVED'}_FIREWALL_HOST:{r.host}")
            continue
        dst = match[0]
        if r.kind == "policy":
            if r.fact.get("default_action") != "allow":
                continue
            note = "the INPUT chain accepts by default"
            add(INTERNET, dst.asset_id, EdgeBasis.CONFIGURED, None, r.via, r.evidence_ref, note)
            for h in hosts:
                if h.asset_id != dst.asset_id and h.ip:
                    add(h.asset_id, dst.asset_id, EdgeBasis.CONFIGURED, None, r.via, r.evidence_ref, note)  # fmt: skip
            continue
        if r.fact.get("action") != "allow" or r.fact.get("direction", "ingress") != "ingress":
            continue
        ports = _ports(r.fact)
        if ports is False:
            continue
        for source in r.fact.get("sources") or []:
            try:
                net = ipaddress.ip_network(str(source), strict=False)
            except ValueError:
                continue  # security-group or prefix-list references: not resolvable to hosts
            if net.prefixlen == 0:
                add(
                    INTERNET, dst.asset_id, EdgeBasis.CONFIGURED, ports, r.via, r.evidence_ref, None
                )
                continue
            if not _internal(net):
                add(INTERNET, dst.asset_id, EdgeBasis.CONFIGURED, ports, r.via, r.evidence_ref,
                    f"only from {net}")  # fmt: skip
            for h in hosts:
                if h.asset_id != dst.asset_id and _inside(h.ip, net):
                    add(h.asset_id, dst.asset_id, EdgeBasis.CONFIGURED, ports, r.via,
                        r.evidence_ref, f"from {net}")  # fmt: skip
    if sg_rules:
        caveats.add(f"SECURITY_GROUP_ATTACHMENTS_UNKNOWN:{sg_rules}")

    unstated = 0
    for s in scans:
        if not s.ports:
            continue
        if s.vantage != "untrusted":
            unstated += 1 if s.vantage is None else 0
            continue
        match = _resolve(s.ip, hosts) if s.ip else []
        if not match and s.hostname:
            match = _resolve(s.hostname, hosts)
        if len(match) != 1:
            label = s.ip or s.hostname or "?"
            caveats.add(f"{'AMBIGUOUS' if match else 'UNRESOLVED'}_SCANNED_HOST:{label}")
            continue
        add(INTERNET, match[0].asset_id, EdgeBasis.OBSERVED, [(p, p) for p in sorted(set(s.ports))],
            s.source, s.evidence_ref, "scan declared as run from an untrusted network")  # fmt: skip
    if unstated:
        caveats.add(f"SCAN_VANTAGE_NOT_STATED:{unstated}")
    if any(e.src == INTERNET and e.basis is EdgeBasis.CONFIGURED for e in g.edges):
        caveats.add("UPSTREAM_FILTERING_NOT_EVALUATED")
    g.edges.sort(key=lambda e: (e.dst, e.src, e.edge_id))
    g.caveats = sorted(caveats)
    return g


def exposure(edges: Iterable[ReachEdge]) -> dict[str, tuple[Exposure, list[str]]]:
    """Per asset: the strongest internet exposure and the edges that support exactly that level."""
    out: dict[str, tuple[Exposure, list[str]]] = {}
    for e in edges:
        if e.src != INTERNET:
            continue
        level: Exposure = "VERIFIED" if e.basis is EdgeBasis.OBSERVED else "CONFIGURED"
        cur = out.get(e.dst)
        if cur is None or RANK[level] > RANK[cur[0]]:
            out[e.dst] = (level, [e.edge_id])
        elif level == cur[0]:
            cur[1].append(e.edge_id)
    return {a: (lvl, sorted(ids)) for a, (lvl, ids) in out.items()}


def paths(edges: Sequence[ReachEdge], targets: Iterable[str], max_hops: int = MAX_HOPS) -> dict[str, list[ReachEdge]]:  # fmt: skip
    """Shortest internet-to-target path per target (observed hops preferred, then by edge id)."""
    best: dict[tuple[str, str], ReachEdge] = {}
    for e in sorted(edges, key=lambda e: (e.basis is not EdgeBasis.OBSERVED, e.edge_id)):
        best.setdefault((e.src, e.dst), e)
    nxt: dict[str, list[str]] = {}
    for src, dst in sorted(best):
        nxt.setdefault(src, []).append(dst)
    parent: dict[str, str] = {}
    depth = {INTERNET: 0}
    queue = deque([INTERNET])
    while queue:
        u = queue.popleft()
        if depth[u] >= max_hops:
            continue
        for v in nxt.get(u, []):
            if v not in depth:
                depth[v], parent[v] = depth[u] + 1, u
                queue.append(v)
    out: dict[str, list[ReachEdge]] = {}
    for t in sorted(set(targets)):
        if t not in parent:
            continue
        hops: list[ReachEdge] = []
        v = t
        while v != INTERNET:
            u = parent[v]
            hops.append(best[(u, v)])
            v = u
        out[t] = hops[::-1]
    return out


def describe_ports(ports: Sequence[tuple[int, int]] | None) -> str:
    if ports is None:
        return "every port"
    return ", ".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports)
