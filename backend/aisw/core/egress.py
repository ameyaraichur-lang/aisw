"""Egress allow-list for AISW hosts (ADR-028): derive it from settings, render host-firewall rules
for the service user, and check from the host that allowed destinations connect and denied ones
do not.

The application already refuses unapproved destinations: scan targets go through net_guard and the
scope manifest (plus ``egress_scan_cidrs``); model, IdP and KMS endpoints are fixed by validated
settings. The firewall is the second, independent layer, so a bug or a compromised process
still cannot reach anything else.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlparse

from sqlalchemy.engine import make_url

from aisw.core.config import ModelProvider, Settings

Role = Literal["api", "worker"]
ROLES: tuple[Role, ...] = ("api", "worker")
Fmt = Literal["nftables", "iptables", "ip6tables"]
Resolver = Callable[[str, int], list[str]]


@dataclass(frozen=True)
class Destination:
    purpose: str
    host: str  # hostname, IP literal or CIDR
    ports: tuple[int, ...]
    roles: tuple[Role, ...]
    proto: str = "tcp"

    @property
    def is_network(self) -> bool:
        try:
            ipaddress.ip_network(self.host, strict=False)
        except ValueError:
            return False
        return True


def _origin(url: str, default_port: int) -> tuple[str, int] | None:
    u = urlparse(url)
    if not u.hostname:
        return None
    return u.hostname.lower(), u.port or (443 if u.scheme == "https" else default_port)


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def destinations(settings: Settings) -> list[Destination]:
    """Every destination an AISW process may connect to, by role. Loopback is always allowed."""
    out: list[Destination] = []

    def add(purpose: str, host: str, ports: Iterable[int], roles: tuple[Role, ...], proto: str = "tcp") -> None:  # fmt: skip
        if not _loopback(host):
            out.append(Destination(purpose, host, tuple(sorted(set(ports))), roles, proto))

    for d in settings.egress_dns:
        add("dns", d, [53], ROLES, "udp")
        add("dns", d, [53], ROLES)
    for purpose, secret, roles in (
        ("database", settings.database_url, ("api",)),
        ("database", settings.worker_database_url or settings.database_url, ("worker",)),
    ):
        if secret is not None:
            url = make_url(secret.get_secret_value())
            if url.host and not url.host.startswith("/"):  # a unix socket needs no egress
                add(purpose, url.host.lower(), [url.port or 5432], roles)  # type: ignore[arg-type]
    if settings.oidc_issuer and (o := _origin(settings.oidc_issuer, 80)):
        add("idp", o[0], [o[1]], ("api",))
    for h in settings.egress_extra_hosts:
        host, _, port = h.rpartition(":") if h.count(":") == 1 else (h, "", "")
        add("idp-extra", host, [int(port) if port else 443], ("api",))
    kms = _origin(settings.kms_addr, 80) if settings.kms_addr else None
    if settings.signing_backend == "transit" and kms:
        add("kms", kms[0], [kms[1]], ROLES)  # api signs, both verify
    if settings.ai_enabled and settings.model_provider is ModelProvider.ASTRA:
        via = settings.astra_proxy or settings.astra_endpoint
        if via and (o := _origin(via, 80)):
            add("astra-proxy" if settings.astra_proxy else "astra", o[0], [o[1]], ("worker",))
    ports = [int(p) for p in settings.egress_scan_ports.split(",")]
    for cidr in settings.egress_zones:
        add("scan-zone", cidr, ports, ("worker",))
    return out


def for_role(dests: Iterable[Destination], role: Role) -> list[Destination]:
    return [d for d in dests if role in d.roles]


def system_resolver(host: str, port: int) -> list[str]:  # pragma: no cover - real DNS
    return sorted({str(i[4][0]) for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


def addresses(
    d: Destination, resolver: Resolver | None
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Firewalls match addresses. Hostnames are resolved only when a resolver is given; otherwise
    they are left out of the rules, which fails closed."""
    if d.is_network:
        return [ipaddress.ip_network(d.host, strict=False)]
    if resolver is None:
        return []
    try:
        return [ipaddress.ip_network(a) for a in resolver(d.host, d.ports[0])]
    except (OSError, ValueError):
        return []


def render(
    dests: list[Destination], fmt: Fmt, *, role: Role, user: str = "aisw",
    resolver: Resolver | None = None,
) -> str:  # fmt: skip
    if not user.isidentifier() and not user.replace("-", "_").isidentifier():
        raise ValueError("service user must be a plain account name")
    rows: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network, Destination]] = []
    unresolved: list[Destination] = []
    for d in for_role(dests, role):
        nets = addresses(d, resolver)
        if not nets:
            unresolved.append(d)
        rows.extend((d.purpose, n, d) for n in nets)
    head = [
        f"# AISW egress allow-list: role={role}, service user {user!r}. Generated by",
        "# tools/egress_check.py from settings (ADR-028); regenerate, do not hand-edit.",
        "# Only the service user's traffic is filtered; everything else on the host is untouched.",
    ]
    for d in unresolved:
        head.append(f"# UNRESOLVED {d.host}:{','.join(map(str, d.ports))} ({d.purpose}): not "
                    "allowed until resolved (fails closed)")  # fmt: skip
    if fmt == "nftables":
        body = ["table inet aisw_egress", "delete table inet aisw_egress", "table inet aisw_egress {",
                "  chain output {", "    type filter hook output priority filter; policy accept;",
                f'    meta skuid != "{user}" accept', '    oif "lo" accept',
                "    ct state established,related accept"]  # fmt: skip
        for purpose, net, d in rows:
            fam = "ip" if net.version == 4 else "ip6"
            ports = ", ".join(map(str, d.ports))
            body.append(f"    {fam} daddr {net} {d.proto} dport {{ {ports} }} accept  # {purpose}")
        body += ['    counter log prefix "aisw-egress-deny " drop', "  }", "}"]
        return "\n".join(["#!/usr/sbin/nft -f", *head, *body]) + "\n"
    version = 4 if fmt == "iptables" else 6
    body = ["# Load with: {} --noflush <file>".format("iptables-restore" if version == 4
                                                      else "ip6tables-restore"),
            "*filter", ":AISW_EGRESS - [0:0]", "-F AISW_EGRESS",
            f"-A OUTPUT -m owner --uid-owner {user} -j AISW_EGRESS", "-A AISW_EGRESS -o lo -j ACCEPT",
            "-A AISW_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"]  # fmt: skip
    for purpose, net, d in rows:
        if net.version != version:
            continue
        ports = ",".join(map(str, d.ports))
        body.append(f"-A AISW_EGRESS -d {net} -p {d.proto} -m multiport --dports {ports} "
                    f'-m comment --comment "{purpose}" -j ACCEPT')  # fmt: skip
    body += ['-A AISW_EGRESS -j LOG --log-prefix "aisw-egress-deny "', "-A AISW_EGRESS -j DROP",
             "COMMIT"]  # fmt: skip
    return "\n".join([*head, *body]) + "\n"


# ---- verification from the host --------------------------------------------------------------------
@dataclass(frozen=True)
class Probe:
    target: str
    expect: Literal["allow", "deny"]
    observed: str
    passed: bool


Connect = Callable[[tuple[str, int], float], Any]


def _connect(addr: tuple[str, int], timeout: float) -> Any:  # pragma: no cover - real sockets
    return socket.create_connection(addr, timeout=timeout)


def probe(
    allowed: Iterable[tuple[str, int]], denied: Iterable[tuple[str, int]], *,
    connect: Connect = _connect, timeout: float = 3.0,
) -> list[Probe]:  # fmt: skip
    """TCP-connect each target. A denied target passes only if the connection fails; pick deny
    canaries that are known to accept connections when no firewall is in the way."""
    out: list[Probe] = []
    for expect, targets in (("allow", allowed), ("deny", denied)):
        for host, port in targets:
            try:
                connect((host, port), timeout).close()
                observed = "connected"
            except TimeoutError:
                observed = "timeout"
            except ConnectionRefusedError:
                observed = "refused"
            except OSError as exc:
                observed = f"error:{type(exc).__name__}"
            ok = observed == "connected" if expect == "allow" else observed != "connected"
            out.append(Probe(f"{host}:{port}", expect, observed, ok))  # type: ignore[arg-type]
    return out


def plan(settings: Settings) -> dict[str, Any]:
    dests = destinations(settings)
    return {
        "roles": {r: [asdict(d) for d in for_role(dests, r)] for r in ROLES},
        "app_level": {
            "scan_targets": "scope manifest + net_guard at preflight and dispatch"
            + (f"; restricted to zones {settings.egress_zones}" if settings.egress_zones else ""),
            "idp": "discovered token/jwks endpoints must be on the issuer host or egress_allowed_hosts",
            "model": "astra endpoint pinned to *.openai.azure.com:443 (or the configured proxy); "
            "ollama loopback only",
            "proxies": "HTTP(S)_PROXY environment variables are ignored by every client",
        },
    }
