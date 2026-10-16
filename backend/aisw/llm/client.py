"""Model clients. The interface has no tool/function parameter: a model cannot be given tools."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import quote, urlparse

from pydantic import SecretStr

from aisw.core.config import astra_endpoint_problem

MAX_RESPONSE_BYTES = 256 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
# Responses API output items that are not tool invocations. Anything else is refused.
ASTRA_ALLOWED_OUTPUT_TYPES = {"message", "reasoning"}


class ModelUnavailable(Exception):  # noqa: N818 - domain term, not an error class hierarchy
    """The model could not be used (disabled, down, slow, oversized or non-conformant transport)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ModelClient(Protocol):
    @property
    def model_id(self) -> str | None: ...

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        """Return the model's raw text. Raises ModelUnavailable; never returns tool calls."""
        ...


class DisabledModelClient:
    """Default client: AI is off, nothing is ever sent anywhere."""

    model_id = None

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        raise ModelUnavailable("AI_DISABLED")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect would be egress to a host we did not configure


class OllamaClient:
    """Talks to a local Ollama-compatible runtime on loopback only. No weights are downloaded here."""

    def __init__(self, endpoint: str, model_id: str) -> None:
        u = urlparse(endpoint)
        if u.scheme not in {"http", "https"} or u.hostname not in LOOPBACK_HOSTS:
            raise ValueError("model endpoint must be a loopback http(s) URL")
        self._base = endpoint.rstrip("/")
        self.model_id = model_id
        self._opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        body = json.dumps(
            {
                "model": self.model_id,
                "stream": False,
                "format": schema,
                "options": {"temperature": 0, "seed": 0},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }  # deliberately no "tools" key
        ).encode()
        req = urllib.request.Request(  # noqa: S310 - scheme and host are validated above
            f"{self._base}/api/chat",
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except TimeoutError as exc:
            raise ModelUnavailable("MODEL_TIMEOUT") from exc
        except (urllib.error.URLError, OSError) as exc:
            if isinstance(getattr(exc, "reason", None), TimeoutError):
                raise ModelUnavailable("MODEL_TIMEOUT") from exc
            raise ModelUnavailable("MODEL_UNREACHABLE") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ModelUnavailable("MODEL_RESPONSE_TOO_LARGE")
        try:
            msg = json.loads(raw)["message"]
            content = msg["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelUnavailable("MODEL_RESPONSE_UNREADABLE") from exc
        if not isinstance(content, str) or msg.get("tool_calls"):
            raise ModelUnavailable("MODEL_TOOL_CALL_REFUSED")
        return content


class AstraClient:
    """Astra (Azure OpenAI Responses API) client. Remote and opt-in only (ADR-020).

    The endpoint must be an Azure OpenAI resource over https; redirects and proxies are refused,
    the request never carries tools, responses are not stored service-side, and the API key is
    only ever placed in the ``api-key`` header.
    """

    def __init__(
        self,
        endpoint: str,
        deployment: str,
        api_key: SecretStr,
        *,
        api_version: str,
        max_output_tokens: int = 2048,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        if problem := astra_endpoint_problem(endpoint):
            raise ValueError(problem)
        if not api_key.get_secret_value().strip():
            raise ValueError("astra api key is empty")
        self._url = (
            f"{endpoint.rstrip('/')}/openai/responses?api-version={quote(api_version, safe='')}"
        )
        self._key = api_key
        self._max_output_tokens = max_output_tokens
        self.model_id = deployment
        self._opener = opener or urllib.request.build_opener(
            _NoRedirect, urllib.request.ProxyHandler({})
        )

    def __repr__(self) -> str:
        return f"AstraClient(url={self._url!r}, deployment={self.model_id!r})"

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        body = json.dumps(
            {
                "model": self.model_id,
                "instructions": system,
                "input": user,
                "store": False,
                "max_output_tokens": self._max_output_tokens,
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "narrative_output",
                        "schema": schema,
                        "strict": False,
                    }
                },
            }  # deliberately no "tools" key
        ).encode()
        req = urllib.request.Request(  # noqa: S310 - endpoint validated above (https, Azure host)
            self._url,
            data=body,
            headers={"content-type": "application/json", "api-key": self._key.get_secret_value()},
            method="POST",
        )
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code in (401, 403):
                raise ModelUnavailable("MODEL_AUTH_FAILED") from None
            if code == 429:
                raise ModelUnavailable("MODEL_RATE_LIMITED") from None
            raise ModelUnavailable("MODEL_UNREACHABLE") from None
        except TimeoutError as exc:
            raise ModelUnavailable("MODEL_TIMEOUT") from exc
        except (urllib.error.URLError, OSError) as exc:
            if isinstance(getattr(exc, "reason", None), TimeoutError):
                raise ModelUnavailable("MODEL_TIMEOUT") from exc
            raise ModelUnavailable("MODEL_UNREACHABLE") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ModelUnavailable("MODEL_RESPONSE_TOO_LARGE")
        return _astra_text(raw)


def _astra_text(raw: bytes) -> str:
    try:
        doc = json.loads(raw)
        items = doc["output"]
        if not isinstance(items, list):
            raise TypeError
    except (ValueError, KeyError, TypeError) as exc:
        raise ModelUnavailable("MODEL_RESPONSE_UNREADABLE") from exc
    if any(
        not isinstance(i, dict) or i.get("type") not in ASTRA_ALLOWED_OUTPUT_TYPES for i in items
    ):
        raise ModelUnavailable("MODEL_TOOL_CALL_REFUSED")
    if doc.get("status") != "completed":
        raise ModelUnavailable("MODEL_RESPONSE_INCOMPLETE")
    texts: list[str] = []
    for item in items:
        if item["type"] != "message":
            continue
        for part in item.get("content") or []:
            kind = part.get("type") if isinstance(part, dict) else None
            if kind == "refusal":
                raise ModelUnavailable("MODEL_REFUSED")
            if kind != "output_text" or not isinstance(part.get("text"), str):
                raise ModelUnavailable("MODEL_RESPONSE_UNREADABLE")
            texts.append(part["text"])
    if not texts:
        raise ModelUnavailable("MODEL_RESPONSE_UNREADABLE")
    return "".join(texts)
