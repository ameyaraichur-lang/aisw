"""AstraClient (Azure OpenAI Responses API) against an in-memory transport. No network, no key."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from email.message import Message
from typing import Any

import pytest
from pydantic import SecretStr

from aisw.core.config import Settings
from aisw.llm.client import AstraClient, DisabledModelClient, ModelUnavailable, _NoRedirect
from aisw.llm.factory import build_model_client
from aisw.llm.gateway import LlmGateway
from tests.evaluation.conftest import make_subject
from tests.evaluation.stub import good_output
from tests.http_server import loopback_only

pytestmark = pytest.mark.evaluation

ENDPOINT = "https://warden-dev.openai.azure.com"
FAKE_KEY = "fake-astra-key-0123456789"  # aisw:allow-secret


class _Resp(io.BytesIO):
    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        self.close()


class FakeOpener(urllib.request.OpenerDirector):
    """Records each request and answers from a script; never opens a socket."""

    def __init__(self, *replies: bytes | Exception) -> None:
        super().__init__()
        self.replies = list(replies)
        self.requests: list[dict[str, Any]] = []

    def open(self, fullurl: Any, data: Any = None, timeout: Any = None) -> Any:
        req: urllib.request.Request = fullurl
        self.requests.append(
            {
                "url": req.full_url,
                "method": req.get_method(),
                "headers": {k.lower(): v for k, v in req.header_items()},
                "body": json.loads(req.data or b"{}"),  # type: ignore[arg-type]
                "timeout": timeout,
            }
        )
        r = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(r, Exception):
            raise r
        return _Resp(r)


def response(*items: dict[str, Any], status: str = "completed") -> bytes:
    return json.dumps({"id": "resp_1", "status": status, "output": list(items)}).encode()


def message(text: str) -> dict[str, Any]:
    return {"type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}  # fmt: skip


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        f"{ENDPOINT}/openai/responses", code, "err", Message(), io.BytesIO(b'{"error":{}}')
    )


def client(opener: FakeOpener, **kw: Any) -> AstraClient:
    return AstraClient(
        ENDPOINT, "gpt-astra", SecretStr(FAKE_KEY), api_version="2025-04-01-preview",
        opener=opener, **kw,
    )  # fmt: skip


def test_request_shape_has_no_tools_and_is_not_stored() -> None:
    s = make_subject()
    op = FakeOpener(response({"type": "reasoning", "summary": []}, message(good_output(s))))
    res = LlmGateway(client(op), timeout=7).narrate(s)
    assert res.status == "VALIDATED" and res.model_id == "gpt-astra"
    (req,) = op.requests
    assert req["method"] == "POST" and req["timeout"] == 7
    assert req["url"] == f"{ENDPOINT}/openai/responses?api-version=2025-04-01-preview"
    assert req["headers"]["api-key"] == FAKE_KEY
    assert "authorization" not in req["headers"]
    body = req["body"]
    assert body["model"] == "gpt-astra" and body["store"] is False
    assert not {"tools", "tool_choice", "functions", "parallel_tool_calls"} & body.keys()
    assert body["text"]["format"]["type"] == "json_schema"
    assert body["text"]["format"]["schema"]["type"] == "object"
    assert body["instructions"].startswith("You write short, factual explanations")
    assert body["input"].startswith("DATA:\n")
    assert FAKE_KEY not in json.dumps(body)


def test_key_is_absent_from_repr_and_errors() -> None:
    c = client(FakeOpener(http_error(500)))
    assert FAKE_KEY not in repr(c)
    with pytest.raises(ModelUnavailable) as e:
        c.complete(system="s", user="u", schema={}, timeout=1)
    assert FAKE_KEY not in repr(e.value) and FAKE_KEY not in str(e.value)
    assert e.value.__cause__ is None  # the HTTP error (and its body) is not chained


@pytest.mark.parametrize(
    ("reply", "code"),
    [
        (http_error(401), "MODEL_AUTH_FAILED"),
        (http_error(403), "MODEL_AUTH_FAILED"),
        (http_error(429), "MODEL_RATE_LIMITED"),
        (http_error(500), "MODEL_UNREACHABLE"),
        (http_error(302), "MODEL_UNREACHABLE"),  # an unfollowed redirect surfaces as an error
        (urllib.error.URLError(ConnectionRefusedError()), "MODEL_UNREACHABLE"),
        (urllib.error.URLError(TimeoutError()), "MODEL_TIMEOUT"),
        (TimeoutError(), "MODEL_TIMEOUT"),
        (b"x" * (300 * 1024), "MODEL_RESPONSE_TOO_LARGE"),
        (b"<html>not json</html>", "MODEL_RESPONSE_UNREADABLE"),
        (b'{"status": "completed"}', "MODEL_RESPONSE_UNREADABLE"),
        (response(), "MODEL_RESPONSE_UNREADABLE"),
        (response({"type": "reasoning"}), "MODEL_RESPONSE_UNREADABLE"),
        (response({"type": "message", "content": [{"type": "output_audio"}]}),
         "MODEL_RESPONSE_UNREADABLE"),
        (response({"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}),
         "MODEL_REFUSED"),
        (response(message("{}"), status="incomplete"), "MODEL_RESPONSE_INCOMPLETE"),
        (response({"type": "function_call", "name": "x", "arguments": "{}"}),
         "MODEL_TOOL_CALL_REFUSED"),
        (response(message("{}"), {"type": "web_search_call"}), "MODEL_TOOL_CALL_REFUSED"),
        (response(message("{}"), {"type": "mcp_call"}), "MODEL_TOOL_CALL_REFUSED"),
        (response("not-an-item"), "MODEL_TOOL_CALL_REFUSED"),  # type: ignore[arg-type]
    ],
)  # fmt: skip
def test_transport_misbehaviour_is_unavailable(reply: bytes | Exception, code: str) -> None:
    with pytest.raises(ModelUnavailable) as e:
        client(FakeOpener(reply)).complete(system="s", user="u", schema={}, timeout=1)
    assert e.value.code == code


def test_auth_failure_and_tool_calls_are_not_retried() -> None:
    for reply in (http_error(401), response({"type": "function_call"})):
        op = FakeOpener(reply)
        res = LlmGateway(client(op)).narrate(make_subject())
        assert res.status == "UNAVAILABLE" and len(op.requests) == 1


def test_rate_limit_is_retried_once_then_unavailable() -> None:
    op = FakeOpener(http_error(429))
    res = LlmGateway(client(op)).narrate(make_subject())
    assert res.status == "UNAVAILABLE" and res.defects == ["MODEL_RATE_LIMITED"]
    assert len(op.requests) == 2


def test_hallucinated_output_is_rejected_by_grounding() -> None:
    s = make_subject()
    bad = good_output(s, summary="Patch CVE-2099-0001 on 10.9.9.9 now.")
    res = LlmGateway(client(FakeOpener(response(message(bad))))).narrate(s)
    assert res.status == "REJECTED" and res.output is None


def test_multi_part_text_is_joined() -> None:
    s = make_subject()
    out = good_output(s)
    item = {"type": "message", "content": [{"type": "output_text", "text": out[:10]},
                                           {"type": "output_text", "text": out[10:]}]}  # fmt: skip
    assert LlmGateway(client(FakeOpener(response(item)))).narrate(s).status == "VALIDATED"


def test_nothing_reaches_the_network_through_the_fake_transport() -> None:
    s = make_subject()
    with loopback_only() as attempts:
        LlmGateway(client(FakeOpener(response(message(good_output(s)))))).narrate(s)
    assert attempts == []


def test_default_transport_refuses_redirects_and_ignores_proxy_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://203.0.113.7:3128")
    c = AstraClient(ENDPOINT, "gpt-astra", SecretStr(FAKE_KEY), api_version="v1")
    handlers = c._opener.handlers  # type: ignore[attr-defined]
    assert any(isinstance(h, _NoRedirect) for h in handlers)
    assert not any(isinstance(h, urllib.request.ProxyHandler) for h in handlers)


@pytest.mark.parametrize(
    "url",
    ["http://warden-dev.openai.azure.com", "https://api.openai.com", "https://127.0.0.1",
     "https://warden-dev.openai.azure.com/openai", "https://warden-dev.openai.azure.com.evil.test"],
)  # fmt: skip
def test_client_refuses_non_azure_endpoints(url: str) -> None:
    with pytest.raises(ValueError):
        AstraClient(url, "gpt-astra", SecretStr(FAKE_KEY), api_version="v1")


def test_client_refuses_an_empty_key() -> None:
    with pytest.raises(ValueError):
        AstraClient(ENDPOINT, "gpt-astra", SecretStr(" "), api_version="v1")


def test_api_version_is_url_encoded() -> None:
    op = FakeOpener(http_error(500))
    c = AstraClient(ENDPOINT, "d", SecretStr(FAKE_KEY), api_version="a&b=c", opener=op)
    with pytest.raises(ModelUnavailable):
        c.complete(system="s", user="u", schema={}, timeout=1)
    assert op.requests[-1]["url"].endswith("?api-version=a%26b%3Dc")


def test_factory_builds_astra_only_when_selected_and_fully_configured() -> None:
    assert isinstance(build_model_client(Settings(model_provider="astra")), DisabledModelClient)
    cfg = Settings(
        ai_enabled=True, model_provider="astra", model_id="gpt-astra", astra_endpoint=ENDPOINT,
        astra_api_key=FAKE_KEY, astra_data_approval_ref="DPA-2026-17",
    )  # fmt: skip
    c = build_model_client(cfg)
    assert isinstance(c, AstraClient) and c.model_id == "gpt-astra"
