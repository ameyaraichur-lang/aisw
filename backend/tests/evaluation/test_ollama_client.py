"""OllamaClient against a local fake runtime on loopback. No model weights, no outside host."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from aisw.core.config import Settings
from aisw.llm.client import DisabledModelClient, ModelUnavailable, OllamaClient
from aisw.llm.factory import build_model_client
from aisw.llm.gateway import LlmGateway
from tests.evaluation.conftest import make_subject
from tests.evaluation.stub import good_output
from tests.http_server import loopback_only

pytestmark = pytest.mark.evaluation


class _Fake:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.mode = "ok"
        self.reply = ""

    def serve(self) -> tuple[ThreadingHTTPServer, str]:
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def do_POST(self) -> None:
                n = int(self.headers.get("content-length", "0"))
                fake.requests.append({"path": self.path, "body": json.loads(self.rfile.read(n))})
                if fake.mode == "redirect":
                    self.send_response(302)  # urllib would follow this, unlike a 307 POST
                    self.send_header("location", "http://203.0.113.9/api/chat")
                    self.end_headers()
                    return
                if fake.mode == "slow":
                    time.sleep(1.5)
                if fake.mode == "huge":
                    payload = b"x" * (300 * 1024)
                elif fake.mode == "tool_calls":
                    payload = json.dumps(
                        {"message": {"content": "{}", "tool_calls": [{"function": {"name": "x"}}]}}
                    ).encode()
                elif fake.mode == "garbage":
                    payload = b"<html>not json</html>"
                else:
                    payload = json.dumps(
                        {"message": {"role": "assistant", "content": fake.reply}}
                    ).encode()
                self.send_response(200)
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def fake() -> Iterator[tuple[_Fake, str]]:
    f = _Fake()
    srv, url = f.serve()
    with loopback_only():
        yield f, url
    srv.shutdown()
    srv.server_close()


def test_request_has_no_tools_and_pins_determinism(fake: tuple[_Fake, str]) -> None:
    f, url = fake
    s = make_subject()
    f.reply = good_output(s)
    res = LlmGateway(OllamaClient(url, "local-model")).narrate(s)
    assert res.status == "VALIDATED" and res.model_id == "local-model"
    body = f.requests[0]["body"]
    assert f.requests[0]["path"] == "/api/chat"
    assert "tools" not in body and "functions" not in body
    assert body["stream"] is False and body["options"] == {"temperature": 0, "seed": 0}
    assert body["format"]["type"] == "object"


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("redirect", "MODEL_UNREACHABLE"),  # redirects are never followed (would leave loopback)
        ("huge", "MODEL_RESPONSE_TOO_LARGE"),
        ("tool_calls", "MODEL_TOOL_CALL_REFUSED"),
        ("garbage", "MODEL_RESPONSE_UNREADABLE"),
    ],
)
def test_transport_misbehaviour_is_unavailable(
    fake: tuple[_Fake, str], mode: str, code: str
) -> None:
    f, url = fake
    f.mode = mode
    res = LlmGateway(OllamaClient(url, "m")).narrate(make_subject())
    assert res.status == "UNAVAILABLE" and res.defects == [code]


def test_slow_model_times_out(fake: tuple[_Fake, str]) -> None:
    f, url = fake
    f.mode = "slow"
    res = LlmGateway(OllamaClient(url, "m"), timeout=0.2).narrate(make_subject())
    assert res.status == "UNAVAILABLE" and res.defects == ["MODEL_TIMEOUT"]


def test_connection_refused_is_unavailable() -> None:
    with loopback_only():
        with pytest.raises(ModelUnavailable) as e:
            OllamaClient("http://127.0.0.1:9", "m").complete(
                system="s", user="u", schema={}, timeout=1
            )
    assert e.value.code == "MODEL_UNREACHABLE"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://10.1.2.3:11434",
        "file:///etc/passwd",
        "http://127.0.0.1.evil.test",
    ],
)
def test_client_refuses_non_loopback_endpoints(url: str) -> None:
    with pytest.raises(ValueError):
        OllamaClient(url, "m")


def test_factory_is_disabled_by_default_and_builds_client_only_when_fully_configured() -> None:
    assert isinstance(build_model_client(Settings()), DisabledModelClient)
    cfg = Settings(ai_enabled=True, model_id="m", model_license="Apache-2.0")
    assert isinstance(build_model_client(cfg), OllamaClient)
