"""A loopback stand-in for Jira (REST v3) and ServiceNow (Table API), for delivery tests only.

Implements just what delivery uses: search by correlation label / correlation_id, and create. It can
be told to create a ticket and then answer too late (the timeout-after-create case), or to answer
an error status, so retries can be shown not to duplicate.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class FakeItsm:
    username: str = "aisw-bot"
    token: str = "fake-token-for-tests"  # noqa: S105 - test-only fake
    jira: list[dict[str, Any]] = field(default_factory=list)
    servicenow: list[dict[str, Any]] = field(default_factory=list)
    slow_creates: int = 0  # the next N creates succeed but reply after `delay`
    delay: float = 1.5
    fail_with: list[int] = field(default_factory=list)  # statuses for the next requests
    requests: list[tuple[str, str]] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def start(self) -> FakeItsm:
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass

            def _send(self, status: int, body: Any) -> None:
                raw = json.dumps(body).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except OSError:  # the client gave up (timeout case)
                    pass

            def _gate(self) -> bool:
                fake.requests.append((self.command, self.path))
                want = (
                    "Basic " + base64.b64encode(f"{fake.username}:{fake.token}".encode()).decode()
                )
                if self.headers.get("Authorization") != want:
                    self._send(401, {"error": "unauthorized"})
                    return False
                if fake.fail_with:
                    self._send(fake.fail_with.pop(0), {"error": "injected"})
                    return False
                return True

            def do_GET(self) -> None:
                if not self._gate():
                    return
                u = urllib.parse.urlparse(self.path)
                q = urllib.parse.parse_qs(u.query)
                if u.path == "/rest/api/3/search/jql":
                    label = q["jql"][0].split('"')[1]
                    hits = [{"key": i["key"]} for i in fake.jira if label in i["fields"]["labels"]]
                    self._send(200, {"issues": hits[: int(q.get("maxResults", ["50"])[0])]})
                elif u.path.startswith("/api/now/table/"):
                    corr = q["sysparm_query"][0].removeprefix("correlation_id=")
                    hits = [r for r in fake.servicenow if r["correlation_id"] == corr]
                    self._send(200, {"result": [{"sys_id": r["sys_id"], "number": r["number"]}
                                                for r in hits[:1]]})  # fmt: skip
                else:
                    self._send(404, {"error": "no route"})

            def do_POST(self) -> None:
                if not self._gate():
                    return
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if self.path == "/rest/api/3/issue":
                    key = f"{body['fields']['project']['key']}-{len(fake.jira) + 1}"
                    fake.jira.append({"key": key, **body})
                    out: dict[str, Any] = {"id": str(len(fake.jira)), "key": key}
                elif self.path.startswith("/api/now/table/"):
                    n = len(fake.servicenow) + 1
                    row = {**body, "sys_id": f"{n:032x}", "number": f"INC{n:07d}"}
                    fake.servicenow.append(row)
                    out = {"result": row}
                else:
                    self._send(404, {"error": "no route"})
                    return
                if fake.slow_creates > 0:
                    fake.slow_creates -= 1
                    time.sleep(fake.delay)
                self._send(201, out)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
