"""Target matching: is a requested target inside the signed scope and outside every exclusion?

Matching is exact-or-narrower, never fuzzy: a request can be equal to or contained in a scoped
target, but never broader. Exclusions always win, across kinds (a host inside an excluded CIDR,
a URL on an excluded host).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from aisw.authz.net_guard import CanonicalURL, NetGuardError, canonicalize_url
from aisw.authz.policy import GatePolicy
from aisw.contracts.manifest import ScopeManifestBody, ScopeTarget

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _network(selector: str) -> Net | None:
    try:
        return ipaddress.ip_network(selector, strict=False)
    except ValueError:
        return None


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def wildcard_reason(target: ScopeTarget, policy: GatePolicy) -> str | None:
    sel = target.selector.strip()
    if "*" in sel or "?" in sel or sel in {"", "any", "all", "0.0.0.0"}:  # noqa: S104
        return "WILDCARD_SCOPE"
    if target.kind == "cidr":
        net = _network(sel)
        if net is None:
            return "INVALID_CIDR"
        if net.prefixlen == 0:
            return "WILDCARD_SCOPE"
        floor = policy.min_cidr_prefix_v4 if net.version == 4 else policy.min_cidr_prefix_v6
        if net.prefixlen < floor:
            return "CIDR_TOO_BROAD"
    if target.kind == "url":
        try:
            if canonicalize_url(sel).host.startswith("*"):
                return "WILDCARD_SCOPE"
        except NetGuardError:
            return None  # reported separately as a malformed URL
    return None


def _path_within(request_path: str, scoped_path: str) -> bool:
    if scoped_path in {"", "/"}:
        return True
    base = scoped_path.rstrip("/")
    return request_path == base or request_path.startswith(base + "/")


def _url_matches(req: CanonicalURL, scoped: CanonicalURL) -> bool:
    return (
        req.scheme == scoped.scheme
        and req.host == scoped.host
        and req.port == scoped.port
        and _path_within(req.path, scoped.path)
    )


def _match(kind: str, selector: str, other: ScopeTarget) -> bool:
    """Does the request (kind, selector) fall inside the single scoped/excluded entry?"""
    if kind == "url":
        try:
            req = canonicalize_url(selector)
        except NetGuardError:
            return False
        if other.kind == "url":
            try:
                return _url_matches(req, canonicalize_url(other.selector))
            except NetGuardError:
                return False
        if other.kind == "host":
            return req.host == other.selector.lower()
        if other.kind == "cidr":
            ip, net = _ip(req.host), _network(other.selector)
            return ip is not None and net is not None and ip.version == net.version and ip in net
        return False
    if kind == "host":
        host = selector.lower()
        if other.kind == "host":
            return host == other.selector.lower()
        if other.kind == "cidr":
            ip, net = _ip(host), _network(other.selector)
            return ip is not None and net is not None and ip.version == net.version and ip in net
        return False
    if kind == "cidr":
        req_net, net = _network(selector), _network(other.selector)
        if other.kind != "cidr" or req_net is None or net is None or req_net.version != net.version:
            return False
        return req_net.subnet_of(net)  # type: ignore[arg-type]
    return other.kind == kind and other.selector == selector  # accounts, regions, asset groups


def _overlaps_exclusion(kind: str, selector: str, excl: ScopeTarget) -> bool:
    """Conservative: any overlap with an exclusion blocks the request."""
    if _match(kind, selector, excl):
        return True
    if kind == "cidr" and excl.kind == "cidr":
        a, b = _network(selector), _network(excl.selector)
        return bool(a and b and a.version == b.version and a.overlaps(b))
    if kind == "cidr" and excl.kind == "host":
        a, ip = _network(selector), _ip(excl.selector)
        return bool(a and ip and a.version == ip.version and ip in a)
    return False


def is_excluded(body: ScopeManifestBody, kind: str, selector: str) -> bool:
    return any(_overlaps_exclusion(kind, selector, e) for e in body.exclusions)


def in_scope(body: ScopeManifestBody, kind: str, selector: str) -> bool:
    """True only if some scoped target contains the request and no exclusion touches it."""
    if is_excluded(body, kind, selector):
        return False
    return any(_match(kind, selector, t) for t in body.targets)


def urls_in_scope(body: ScopeManifestBody) -> Iterable[CanonicalURL]:
    for t in body.targets:
        if t.kind == "url":
            try:
                yield canonicalize_url(t.selector)
            except NetGuardError:
                continue
