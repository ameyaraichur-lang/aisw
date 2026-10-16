"""A loopback emulator of the Transit secrets engine subset AISW uses (ADR-027). Test-only.

Implements key create/read/rotate/config and sign for ``ed25519`` keys with Vault's semantics:
signing uses the latest version unless ``key_version`` is given; versions below
``min_encryption_version`` are refused for signing; keys are not exportable. Tokens carry
capabilities, so least privilege (the app token cannot rotate) is testable.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_CAPS = frozenset({"read", "sign"})
ADMIN_CAPS = frozenset({"read", "sign", "create", "rotate", "config"})


class _Key:
    def __init__(self) -> None:
        self.versions: dict[int, Ed25519PrivateKey] = {1: Ed25519PrivateKey.generate()}
        self.created: dict[int, str] = {1: _now()}
        self.min_encryption_version = 0
        self.min_decryption_version = 1

    @property
    def latest(self) -> int:
        return max(self.versions)

    def describe(self, name: str) -> dict[str, Any]:
        keys = {}
        for v, k in self.versions.items():
            raw = k.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            keys[str(v)] = {"public_key": base64.b64encode(raw).decode(), "name": "ed25519",
                            "creation_time": self.created[v]}  # fmt: skip
        return {
            "name": name, "type": "ed25519", "exportable": False, "deletion_allowed": False,
            "latest_version": self.latest, "min_encryption_version": self.min_encryption_version,
            "min_decryption_version": self.min_decryption_version, "keys": keys,
            "supports_signing": True,
        }  # fmt: skip


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class TransitEmulator:
    def __init__(self, *, mount: str = "transit") -> None:
        self.mount = mount
        self.keys: dict[str, _Key] = {}
        self.tokens: dict[str, frozenset[str]] = {}
        self.app_token = self.issue(APP_CAPS)
        self.admin_token = self.issue(ADMIN_CAPS)
        self.down = False
        self.requests: list[tuple[str, str]] = []
        self.tamper_next_signature = False
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.addr = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def issue(self, caps: frozenset[str]) -> str:
        token = f"emu.{secrets.token_urlsafe(18)}"
        self.tokens[token] = caps
        return token

    def create(self, name: str) -> None:
        self.keys.setdefault(name, _Key())

    def start(self) -> TransitEmulator:
        self._thread.start()
        return self

    def __enter__(self) -> TransitEmulator:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        emu = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass

            def _send(self, code: int, body: dict[str, Any] | None = None) -> None:
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _route(self, method: str) -> None:
                emu.requests.append((method, self.path))
                if emu.down:
                    self._send(503, {"errors": ["sealed"]})
                    return
                caps = emu.tokens.get(self.headers.get("X-Vault-Token", ""))
                if caps is None:
                    self._send(403, {"errors": ["permission denied"]})
                    return
                prefix = f"/v1/{emu.mount}/"
                if not self.path.startswith(prefix):
                    self._send(404, {"errors": ["no handler"]})
                    return
                parts = self.path[len(prefix) :].split("/")
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                op = self._op(method, parts)
                if op is None:
                    self._send(405, {"errors": ["unsupported"]})
                    return
                if op not in caps:
                    self._send(403, {"errors": ["permission denied"]})
                    return
                getattr(self, f"_do_{op}")(parts[1], body)

            @staticmethod
            def _op(method: str, parts: list[str]) -> str | None:
                if len(parts) == 2 and parts[0] == "keys":
                    return {"GET": "read", "POST": "create"}.get(method)
                if len(parts) == 3 and parts[0] == "keys" and method == "POST":
                    return {"rotate": "rotate", "config": "config"}.get(parts[2])
                if len(parts) == 2 and parts[0] == "sign" and method == "POST":
                    return "sign"
                return None

            def _key(self, name: str) -> _Key | None:
                k = emu.keys.get(name)
                if k is None:
                    self._send(404, {"errors": ["key not found"]})
                return k

            def _do_read(self, name: str, _: dict[str, Any]) -> None:
                if (k := self._key(name)) is not None:
                    self._send(200, {"data": k.describe(name)})

            def _do_create(self, name: str, body: dict[str, Any]) -> None:
                if body.get("type", "ed25519") != "ed25519":
                    self._send(400, {"errors": ["only ed25519 is emulated"]})
                    return
                emu.create(name)
                self._send(204)

            def _do_rotate(self, name: str, _: dict[str, Any]) -> None:
                if (k := self._key(name)) is not None:
                    v = k.latest + 1
                    k.versions[v] = Ed25519PrivateKey.generate()
                    k.created[v] = _now()
                    self._send(200, {"data": k.describe(name)})

            def _do_config(self, name: str, body: dict[str, Any]) -> None:
                if (k := self._key(name)) is None:
                    return
                v = body.get("min_encryption_version")
                if not isinstance(v, int) or not 0 <= v <= k.latest:
                    self._send(400, {"errors": ["invalid min_encryption_version"]})
                    return
                k.min_encryption_version = v
                self._send(200, {"data": k.describe(name)})

            def _do_sign(self, name: str, body: dict[str, Any]) -> None:
                if (k := self._key(name)) is None:
                    return
                v = body.get("key_version") or k.latest
                if not isinstance(v, int) or v not in k.versions:
                    self._send(400, {"errors": ["invalid key version"]})
                    return
                if v < k.min_encryption_version:
                    self._send(400, {"errors": ["requested version for signing is less than the "
                                                "minimum encryption key version"]})  # fmt: skip
                    return
                try:
                    data = base64.b64decode(body.get("input", ""), validate=True)
                except ValueError:
                    self._send(400, {"errors": ["input is not base64"]})
                    return
                sig = k.versions[v].sign(data)
                if emu.tamper_next_signature:
                    emu.tamper_next_signature = False
                    sig = bytes([sig[0] ^ 1]) + sig[1:]
                encoded = base64.b64encode(sig).decode()
                self._send(200, {"data": {"signature": f"vault:v{v}:{encoded}", "key_version": v}})

            def do_GET(self) -> None:
                self._route("GET")

            def do_POST(self) -> None:
                self._route("POST")

        return Handler
