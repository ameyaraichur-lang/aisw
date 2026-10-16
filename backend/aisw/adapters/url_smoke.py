"""PASSIVE_HTTP_SMOKE adapter: one bounded, read-only probe of an exactly-registered URL.

What it does: reuse the gateway's pinned DNS answer, a TLS handshake with certificate metadata, and
ONE request (GET or HEAD) per hop, following redirects only when the gateway re-validates each
target against the signed scope and egress policy.

What it deliberately does NOT do: resolve names itself (it connects only to pinned addresses, so
DNS rebinding cannot redirect it), crawl, submit forms, fuzz, enumerate ports, send cookies or
credentials, read or store a response body, or continue after a failed TLS verification.

Anything the target sends (headers, certificate fields) is untrusted DATA: truncated, newline-
stripped, redacted again at ingest, and never interpreted.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import Field

from aisw.adapters.normalized import (
    NormalizedAsset,
    NormalizedBatch,
    NormalizedObservation,
)
from aisw.authz.net_guard import CanonicalURL, NetGuardError, canonicalize_url
from aisw.contracts.base import StrictModel
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterCapability, AdapterJob, AdapterOutput

ADAPTER_ID = "url_smoke"
PROFILE_ID = "PASSIVE_HTTP_SMOKE"
TOOL = "aisw-url-smoke"
TOOL_VERSION = "0.1.0"
USER_AGENT = f"AISW-PassiveSmoke/{TOOL_VERSION}"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
KEPT_HEADERS = (
    "server", "content-type", "content-length", "content-encoding", "cache-control", "date",
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy", "access-control-allow-origin",
    "location",
)  # fmt: skip
MAX_VALUE = 512
NOTICE = "Public URL smoke test — not a security certification"


class UrlSmokeParams(StrictModel):
    method: Literal["GET", "HEAD"] = "GET"
    max_redirects: int = Field(default=3, ge=0, le=5)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=15.0)


def url_asset_id(url: CanonicalURL) -> str:
    origin = f"{url.scheme}://{url.host}:{url.port}"
    return "url-" + hashlib.sha256(origin.encode()).hexdigest()[:12]


def _clean(value: str) -> str:
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())[:MAX_VALUE]


def _name(rdn: x509.Name) -> str:
    return _clean(rdn.rfc4514_string())


def cert_metadata(der: bytes, now: datetime) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)][:50]
        names += [str(v) for v in san.get_values_for_type(x509.IPAddress)][:50]
    except x509.ExtensionNotFound:
        names = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA-{key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"EC-{key.curve.name}"
    else:
        key_desc = type(key).__name__
    not_after = cert.not_valid_after_utc
    sig = cert.signature_hash_algorithm
    return {
        "subject": _name(cert.subject), "issuer": _name(cert.issuer),
        "self_signed": cert.subject == cert.issuer, "serial": format(cert.serial_number, "x")[:64],
        "not_before": cert.not_valid_before_utc.isoformat(), "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days, "san": [_clean(n) for n in names],
        "public_key": key_desc, "signature_hash": sig.name if sig else None,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }  # fmt: skip


class UrlSmokeAdapter:
    def __init__(
        self, *, ca_file: Path | None = None, clock: Callable[[], datetime] | None = None
    ) -> None:
        # The trust store is configured by the operator/deployment only; neither the manifest nor
        # the request can change it. None means the platform default trust store.
        self._ca_file = ca_file
        self._clock = clock or (lambda: datetime.now(UTC))
        self.capability = AdapterCapability(
            adapter_id=ADAPTER_ID, version=TOOL_VERSION, domains=frozenset({"url"}),
            profiles={PROFILE_ID: ProfileClass.READ_ONLY}, target_kinds=frozenset({"url"}),
            param_model=UrlSmokeParams,
        )  # fmt: skip

    def estimate_requests(self, params: dict[str, Any]) -> int:
        return 1 + int(params.get("max_redirects", 3))  # worst case: the redirect budget is spent

    # ------------------------------------------------------------------ execution
    def execute(self, job: AdapterJob) -> AdapterOutput:
        params = UrlSmokeParams.model_validate(job.params)
        url = canonicalize_url(job.target_selector)
        if not job.pinned_addresses:  # never fall back to resolving a name ourselves
            raise RuntimeError("no pinned addresses supplied by the gateway")
        started = self._clock()
        hops: list[dict[str, Any]] = []
        chain = [str(url)]
        warnings: list[str] = []
        errors: list[str] = []
        current, addrs = url, job.pinned_addresses
        status: Literal["SUCCEEDED", "PARTIAL", "FAILED"] = "SUCCEEDED"
        dns = [{"host": url.host, "addresses": list(addrs), "pinned_by": "tool-gateway",
                "at": started.isoformat()}]  # fmt: skip
        for n in range(params.max_redirects + 1):
            hop = self._probe(current, addrs, params)
            hops.append(hop)
            resp = hop["response"]
            if hop["error"]:
                code = str(hop["error"])
                if n == 0 and code.startswith(("CONNECT_FAILED", "TLS_HANDSHAKE_FAILED")):
                    status = "FAILED"
                    errors.append(code)
                else:
                    status = "PARTIAL"
                    warnings.append(code)
                break
            if resp is None or resp["status"] not in REDIRECT_STATUSES:
                break
            location = resp["headers"].get("location")
            if not location:
                warnings.append("REDIRECT_WITHOUT_LOCATION")
                status = "PARTIAL"
                break
            if n == params.max_redirects:
                warnings.append("TOO_MANY_REDIRECTS")
                hop["redirect_blocked"] = "TOO_MANY_REDIRECTS"
                status = "PARTIAL"
                break
            try:
                if job.vet_redirect is None:
                    raise NetGuardError("REDIRECT_VETTING_UNAVAILABLE")
                vetted = job.vet_redirect(current, location, n + 1)
            except NetGuardError as exc:
                warnings.append(f"REDIRECT_BLOCKED:{exc.code}")
                hop["redirect_blocked"] = exc.code
                status = "PARTIAL"
                break
            current, addrs = vetted.url, vetted.addresses
            chain.append(str(current))
            dns.append({"host": current.host, "addresses": list(addrs), "pinned_by": "tool-gateway",
                        "at": self._clock().isoformat()})  # fmt: skip
        raw: dict[str, Any] = {
            "tool": TOOL, "version": TOOL_VERSION, "profile": PROFILE_ID, "notice": NOTICE,
            "target": str(url), "method": params.method, "dns": dns, "hops": hops,
            "redirect_chain": chain,
            "request_count": sum(1 for h in hops if h["request_sent"]),
            "started_at": started.isoformat(), "ended_at": self._clock().isoformat(),
            "body_stored": False,
            "limitations": [
                "Passive single-path probe: no crawling, forms, fuzzing, port enumeration or scanning",
                "Response bodies are never read or stored",
                NOTICE,
            ],
        }  # fmt: skip
        return AdapterOutput(
            status=status, tool=TOOL, tool_version=TOOL_VERSION, collected_at=self._clock(),
            raw=raw, warnings=warnings, errors=errors,
        )  # fmt: skip

    def _context(self, *, verify: bool) -> ssl.SSLContext:
        if verify:
            ctx = ssl.create_default_context(cafile=str(self._ca_file) if self._ca_file else None)
        else:  # metadata-only handshake after a failed verification: no data is ever sent on it
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def _probe(
        self, url: CanonicalURL, addrs: tuple[str, ...], p: UrlSmokeParams
    ) -> dict[str, Any]:
        hop: dict[str, Any] = {
            "url": str(url), "scheme": url.scheme, "host": url.host, "port": url.port,
            "method": p.method, "connect": None, "tls": None, "response": None, "error": None,
            "request_sent": False, "redirect_blocked": None,
        }  # fmt: skip
        sock = self._connect(addrs, url.port, p.timeout_seconds, hop)
        if sock is None:
            return hop
        try:
            channel: socket.socket | ssl.SSLSocket = sock
            if url.scheme == "https":
                try:
                    tls = self._context(verify=True).wrap_socket(sock, server_hostname=url.host)
                except ssl.SSLCertVerificationError as exc:
                    hop["tls"] = {"verified": False, "verify_error": _clean(exc.verify_message or str(exc)),
                                  "verify_code": exc.verify_code, **self._peek_metadata(hop["connect"]["ip"], url)}  # fmt: skip
                    hop["error"] = "TLS_VERIFY_FAILED"  # nothing is sent over an unverified channel
                    return hop
                except (ssl.SSLError, OSError) as exc:
                    hop["error"] = f"TLS_HANDSHAKE_FAILED:{type(exc).__name__}"
                    return hop
                hop["tls"] = {"verified": True, **self._session_info(tls)}
                channel = tls
            return self._request(channel, url, p, hop)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def _connect(
        self, addrs: tuple[str, ...], port: int, timeout: float, hop: dict[str, Any]
    ) -> socket.socket | None:
        last = "NO_ADDRESS"
        for ip in addrs:  # ONLY pinned, already-vetted addresses
            try:
                s = socket.create_connection((ip, port), timeout=timeout)
            except OSError as exc:
                last = type(exc).__name__
                continue
            hop["connect"] = {"ip": ip, "port": port}
            return s
        hop["error"] = f"CONNECT_FAILED:{last}"
        return None

    def _session_info(self, tls: ssl.SSLSocket) -> dict[str, Any]:
        der = tls.getpeercert(binary_form=True)
        cipher = tls.cipher()
        info: dict[str, Any] = {"version": tls.version(), "cipher": cipher[0] if cipher else None}
        if der:
            info["certificate"] = cert_metadata(der, self._clock())
        return info

    def _peek_metadata(self, ip: str, url: CanonicalURL) -> dict[str, Any]:
        """Second handshake with verification off, ONLY to describe the certificate we rejected."""
        try:
            raw = socket.create_connection((ip, url.port), timeout=5)
            with self._context(verify=False).wrap_socket(raw, server_hostname=url.host) as t:
                return self._session_info(t)
        except (ssl.SSLError, OSError, ValueError):
            return {}

    def _request(
        self, channel: socket.socket | ssl.SSLSocket, url: CanonicalURL, p: UrlSmokeParams,
        hop: dict[str, Any],
    ) -> dict[str, Any]:  # fmt: skip
        conn: http.client.HTTPConnection
        if url.scheme == "https":  # context unused: the socket is already TLS-wrapped and verified
            conn = http.client.HTTPSConnection(
                url.host, url.port, context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            )
        else:
            conn = http.client.HTTPConnection(url.host, url.port)
        conn.sock = channel  # already connected to the pinned address
        try:
            hop["request_sent"] = True
            conn.request(
                p.method, url.path + (f"?{url.query}" if url.query else ""),
                headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity",
                         "Connection": "close"},
            )  # fmt: skip
            resp = conn.getresponse()
            headers = {k.lower(): v for k, v in resp.getheaders()}
            hop["response"] = {
                "status": resp.status, "reason": _clean(resp.reason or ""),
                "headers": {k: _clean(headers[k]) for k in KEPT_HEADERS if k in headers},
                "header_count": len(headers), "set_cookie_present": "set-cookie" in headers,
                "body_bytes_read": 0,  # the body is never read; the connection is simply closed
            }  # fmt: skip
        except TimeoutError:
            hop["error"] = "READ_TIMEOUT"
        except (http.client.HTTPException, OSError) as exc:
            hop["error"] = f"HTTP_PROTOCOL_ERROR:{type(exc).__name__}"
        finally:
            conn.sock = None  # we close the socket ourselves
        return hop

    # ------------------------------------------------------------------ normalization
    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        raw = output.raw
        url = canonicalize_url(raw["target"])
        asset_id = url_asset_id(url)
        hops: list[dict[str, Any]] = raw["hops"]
        first = hops[0]
        batch = NormalizedBatch()
        if first["connect"] is None:
            batch.assets.append(NormalizedAsset(
                asset_id, url.host, {"scheme": url.scheme}, "UNREACHABLE", str(first["error"]),
                asset_type="url", native_ids={"origin": f"{url.scheme}://{url.host}:{url.port}"},
            ))  # fmt: skip
            return batch
        batch.assets.append(NormalizedAsset(
            asset_id, url.host, {"scheme": url.scheme}, "SCANNED", None, asset_type="url",
            native_ids={"origin": f"{url.scheme}://{url.host}:{url.port}", "hostname": url.host},
        ))  # fmt: skip

        def obs(rule_id: str, value: Any) -> None:
            oid = hashlib.sha256(f"{run_id}|{task_id}|{asset_id}|{rule_id}".encode()).hexdigest()
            batch.observations.append(
                NormalizedObservation(f"o-{oid[:24]}", asset_id, rule_id, value)
            )

        tls = first["tls"]
        if url.scheme == "https" and tls is not None:
            obs("tls.verified", bool(tls.get("verified")))
            if tls.get("version"):
                obs("tls.protocol", tls["version"])
            cert = tls.get("certificate")
            if cert:
                obs("tls.cert_days_remaining", cert["days_remaining"])
        final = next((h for h in reversed(hops) if h["response"] is not None), None)
        if final is not None:
            r = final["response"]
            obs("http.response_received", True)
            if final["scheme"] == "https":
                obs("http.hsts_present", "strict-transport-security" in r["headers"])
            obs("http.x_content_type_options", r["headers"].get("x-content-type-options", "absent"))
        elif first["error"] not in {"TLS_VERIFY_FAILED"}:
            obs("http.response_received", False)
        if any(h["redirect_blocked"] for h in hops):
            obs("http.redirects_within_scope", False)
        elif len(hops) > 1:
            obs("http.redirects_within_scope", True)
        return batch
