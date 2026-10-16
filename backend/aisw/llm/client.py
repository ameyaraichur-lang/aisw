"""Model clients. The interface has no tool/function parameter: a model cannot be given tools."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlparse

MAX_RESPONSE_BYTES = 256 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


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
