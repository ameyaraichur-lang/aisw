"""URL canonicalisation and SSRF guard (ADR-012, blueprint J.6).

Pure library: no network access happens here except through an injected resolver, so every
rule is testable with a fake. Callers must connect to the *pinned* addresses returned by
``resolve_and_vet`` (never re-resolve), and must call ``vet_redirect`` for every hop.

Rules enforced:
* only http/https; no user-info; no whitespace/control characters/backslashes; IDNA-normalised
  lower-case hosts; ambiguous numeric IPv4 spellings (decimal, octal, hex, short forms) rejected
* port must be explicitly approved by the manifest
* every A/AAAA answer must be globally routable; loopback, private, link-local, multicast,
  unspecified, reserved, CGNAT, documentation, ULA, site-local and cloud-metadata ranges are
  blocked, including IPv4-mapped, 6to4 and NAT64 embeddings. Python's ``is_global`` is NOT
  trusted alone (it reports multicast ``ff02::1`` and NAT64-wrapped loopback as global)
* internal ranges are reachable only via an explicit ``internal_ranges`` authorisation carried in
  the signed manifest; cloud-metadata addresses are never reachable, authorised or not
* redirects are re-validated against scope and egress policy; cross-host/port needs the target to
  be explicitly in scope
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urljoin, urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 5

# Never reachable, even with an internal-range authorisation.
_METADATA_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # AWS/GCP/Azure/OpenStack IMDS
        "169.254.170.2/32",  # ECS task metadata
        "100.100.100.200/32",  # Alibaba
        "192.0.0.192/32",  # Oracle
        "fd00:ec2::254/128",  # AWS IMDS IPv6
    )
]
# Embedded-IPv4 transition prefixes are unwrapped and re-checked.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")  # local-use NAT64: never public
_EXTRA_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "100.64.0.0/10",  # CGNAT
        "198.18.0.0/15",  # benchmarking
        "fec0::/10",  # deprecated site-local
        "2001:db8::/32",  # documentation
        "::/96",  # IPv4-compatible (deprecated)
    )
]


class NetGuardError(ValueError):
    """Carries a stable machine-readable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class CanonicalURL:
    scheme: str
    host: str  # lower-case ASCII (IDNA) or normalised IP literal
    port: int
    path: str
    query: str

    @property
    def origin(self) -> str:
        default = DEFAULT_PORTS[self.scheme]
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")

    def __str__(self) -> str:
        return self.origin + self.path + (f"?{self.query}" if self.query else "")

    @property
    def is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True


# ---------------------------------------------------------------------------------------------
# canonicalisation
# ---------------------------------------------------------------------------------------------
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_NUMERIC_LABEL = re.compile(r"^(0[xX][0-9a-fA-F]*|\d+)$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _canonical_host(raw_host: str) -> str:
    if not raw_host:
        raise NetGuardError("EMPTY_HOST")
    if ":" in raw_host:  # IPv6 literal (urlsplit already stripped the brackets)
        try:
            return str(ipaddress.IPv6Address(raw_host.split("%", 1)[0]))
        except ValueError as exc:
            raise NetGuardError("MALFORMED_HOST", "invalid IPv6 literal") from exc
    host = raw_host[:-1] if len(raw_host) > 1 and raw_host.endswith(".") else raw_host
    labels = host.split(".")
    if all(_NUMERIC_LABEL.match(lbl) for lbl in labels):
        # Looks like an IPv4 address: accept ONLY canonical dotted-quad, reject 127.1, 0x7f..., etc.
        if len(labels) == 4 and all(lbl.isdigit() and str(int(lbl)) == lbl for lbl in labels):
            try:
                return str(ipaddress.IPv4Address(host))
            except ValueError as exc:
                raise NetGuardError("MALFORMED_HOST", "invalid IPv4 literal") from exc
        raise NetGuardError("AMBIGUOUS_IP_FORMAT", raw_host)
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NetGuardError("MALFORMED_HOST", "not IDNA-encodable") from exc
    if len(ascii_host) > 253 or not all(_LABEL.match(lbl) for lbl in ascii_host.split(".")):
        raise NetGuardError("MALFORMED_HOST", "invalid hostname")
    return ascii_host


def canonicalize_url(raw: str, *, schemes: Iterable[str] = ("http", "https")) -> CanonicalURL:
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        raise NetGuardError("MALFORMED_URL")
    if _BAD_CHARS.search(raw):
        raise NetGuardError("MALFORMED_URL", "whitespace, control or backslash characters")
    try:
        parts: SplitResult = urlsplit(raw)
        port_raw = parts.port  # raises ValueError on invalid ports
    except ValueError as exc:
        raise NetGuardError("MALFORMED_URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in set(schemes) or scheme not in DEFAULT_PORTS:
        raise NetGuardError("UNSUPPORTED_SCHEME", scheme or "(none)")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise NetGuardError("USERINFO_NOT_ALLOWED")
    if not parts.hostname:
        raise NetGuardError("EMPTY_HOST")
    host = _canonical_host(parts.hostname)
    if port_raw is not None and not 1 <= port_raw <= 65535:
        raise NetGuardError("INVALID_PORT")
    port = port_raw if port_raw is not None else DEFAULT_PORTS[scheme]
    return CanonicalURL(scheme, host, port, parts.path or "/", parts.query)


# ---------------------------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------------------------
def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip.teredo is not None:
            return ip.teredo[1]
    return None


def block_reason(
    ip: IPAddress, internal_ranges: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = ()
) -> str | None:
    """Return a reason code if the address must not be contacted, else None."""
    embedded = _embedded_ipv4(ip)
    if embedded is not None:  # judge the wrapped IPv4 address, never the wrapper
        inner = block_reason(embedded, internal_ranges)
        return f"EMBEDDED_{inner}" if inner else None
    if any(ip in net for net in _METADATA_NETS if net.version == ip.version):
        return "CLOUD_METADATA"  # never authorisable
    if isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_LOCAL:
        return "NAT64_LOCAL_USE"
    allowed_internal = any(ip in net for net in internal_ranges if net.version == ip.version)
    if allowed_internal:
        return None
    if ip.is_multicast:
        return "MULTICAST"
    if ip.is_unspecified:
        return "UNSPECIFIED"
    if ip.is_loopback:
        return "LOOPBACK"
    if ip.is_link_local:
        return "LINK_LOCAL"
    if ip.is_private:
        return "PRIVATE"
    if ip.is_reserved:
        return "RESERVED"
    if any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version):
        return "NON_ROUTABLE"
    if not ip.is_global:
        return "NON_GLOBAL"
    return None


def parse_internal_ranges(
    raw: Iterable[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw:
        try:
            net = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise NetGuardError("INVALID_INTERNAL_RANGE", item) from exc
        if net.prefixlen == 0 or (net.version == 4 and net.prefixlen < 8):
            raise NetGuardError("INTERNAL_RANGE_TOO_BROAD", item)
        out.append(net)
    return out


# ---------------------------------------------------------------------------------------------
# resolution and vetting
# ---------------------------------------------------------------------------------------------
def system_resolver(host: str, port: int) -> list[str]:  # pragma: no cover - real network
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True)
class VettedTarget:
    """Connect ONLY to these addresses. Re-resolving would reopen the DNS-rebinding window."""

    url: CanonicalURL
    addresses: tuple[str, ...]
    warnings: tuple[str, ...] = field(default=())


def resolve_and_vet(
    url: CanonicalURL,
    *,
    allowed_ports: Iterable[int],
    internal_ranges: Iterable[str] = (),
    resolver: Resolver = system_resolver,
    previous: VettedTarget | None = None,
) -> VettedTarget:
    """Resolve A/AAAA and vet every answer. Call at preflight AND again immediately before
    dispatch (pass the preflight result as ``previous`` to detect and report DNS changes)."""
    if url.port not in set(allowed_ports):
        raise NetGuardError("PORT_NOT_APPROVED", str(url.port))
    ranges = parse_internal_ranges(internal_ranges)
    if url.is_ip_literal:
        answers = [url.host]
    else:
        try:
            answers = list(resolver(url.host, url.port))
        except OSError as exc:
            raise NetGuardError("DNS_RESOLUTION_FAILED", url.host) from exc
    if not answers:
        raise NetGuardError("DNS_NO_ANSWER", url.host)
    parsed: list[IPAddress] = []
    for a in answers:
        try:
            parsed.append(ipaddress.ip_address(a))
        except ValueError as exc:
            raise NetGuardError("DNS_INVALID_ANSWER", a) from exc
    for ip in parsed:  # ONE bad answer denies the whole target
        reason = block_reason(ip, ranges)
        if reason:
            raise NetGuardError(f"BLOCKED_ADDRESS_{reason}", f"{url.host} -> {ip}")
    addresses = tuple(sorted(str(ip) for ip in parsed))
    warnings: tuple[str, ...] = ()
    if previous is not None and set(previous.addresses) != set(addresses):
        warnings = ("DNS_ANSWER_CHANGED_SINCE_PREFLIGHT",)
    return VettedTarget(url, addresses, warnings)


def vet_redirect(
    current: CanonicalURL,
    location: str,
    *,
    hop: int,
    in_scope: Callable[[CanonicalURL], bool],
    allowed_ports: Iterable[int],
    internal_ranges: Iterable[str] = (),
    resolver: Resolver = system_resolver,
) -> VettedTarget:
    """Re-validate a redirect target against scope and egress policy."""
    if hop > MAX_REDIRECTS:
        raise NetGuardError("TOO_MANY_REDIRECTS")
    if not isinstance(location, str) or _BAD_CHARS.search(location):
        raise NetGuardError("MALFORMED_REDIRECT")
    nxt = canonicalize_url(urljoin(str(current), location))
    if (nxt.host, nxt.port) != (current.host, current.port) and not in_scope(nxt):
        raise NetGuardError("REDIRECT_OUT_OF_SCOPE", f"{current.origin} -> {nxt.origin}")
    if not in_scope(nxt):
        raise NetGuardError("REDIRECT_OUT_OF_SCOPE", str(nxt))
    return resolve_and_vet(
        nxt, allowed_ports=allowed_ports, internal_ranges=internal_ranges, resolver=resolver
    )
