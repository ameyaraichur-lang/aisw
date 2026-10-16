"""Control-plane HTTP for configured infrastructure endpoints (IdP, KMS).

Proxy environment variables are ignored, redirects are refused, responses are size-capped and
every call has a timeout. Callers validate the URL before building the request.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

MAX_BYTES = 512 * 1024


class HttpError(Exception):
    def __init__(self, message: str, status: int | None = None, body: bytes = b"") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def fetch(req: urllib.request.Request, *, timeout: float = 10, max_bytes: int = MAX_BYTES) -> bytes:
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 - callers validate URLs
            raw: bytes = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        body = exc.read(4096) if exc.fp is not None else b""
        exc.close()
        raise HttpError(f"answered {exc.code}", exc.code, body) from None
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise HttpError("unreachable") from exc
    if len(raw) > max_bytes:
        raise HttpError("response too large")
    return raw
