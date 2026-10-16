"""Ticket delivery to Jira or ServiceNow: find-then-create on the draft's correlation key.

A delivery that timed out may still have created the ticket. The next attempt therefore looks the
key up first and returns the existing ticket, so a retry never creates a duplicate. Calls go
through the control-plane HTTP helper: no proxy, no redirects, size cap, timeout. The client never
updates, transitions or closes a ticket.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aisw.core.config import Settings
from aisw.core.safe_http import HttpError, fetch
from aisw.itsm.render import Target, correlation_key

Fetch = Callable[[urllib.request.Request, float], bytes]


class DeliveryError(Exception):
    """``code`` is safe to store and show; it never carries a credential or a response body."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code, self.retryable = code, retryable


@dataclass(frozen=True)
class Delivered:
    external_ref: str
    url: str | None
    created: bool  # False when an earlier attempt had already created it


def _default_fetch(req: urllib.request.Request, timeout: float) -> bytes:
    return fetch(req, timeout=timeout)


@dataclass
class ItsmClient:
    target: Target
    base_url: str
    username: str
    token: str
    timeout: float = 10.0
    servicenow_table: str = "incident"
    fetch: Fetch = _default_fetch

    def _req(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        auth = base64.b64encode(f"{self.username}:{self.token}".encode()).decode()
        req = urllib.request.Request(  # noqa: S310 - base_url is validated by Settings
            self.base_url.rstrip("/") + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Basic {auth}", "Accept": "application/json",
                     "Content-Type": "application/json"},
        )  # fmt: skip
        try:
            raw = self.fetch(req, self.timeout)
        except HttpError as exc:
            if exc.status is None:
                raise DeliveryError("ITSM_UNREACHABLE", retryable=True) from None
            if exc.status in {401, 403}:
                raise DeliveryError(f"ITSM_REFUSED_{exc.status}", retryable=False) from None
            if exc.status == 429 or exc.status >= 500:
                raise DeliveryError(f"ITSM_ERROR_{exc.status}", retryable=True) from None
            raise DeliveryError(f"ITSM_REJECTED_{exc.status}", retryable=False) from None
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise DeliveryError("ITSM_BAD_RESPONSE", retryable=True) from None

    def find(self, outbox_id: str) -> Delivered | None:
        key = correlation_key(outbox_id)
        if self.target == "jira":
            q = urllib.parse.urlencode(
                {"jql": f'labels = "{key}"', "maxResults": 1, "fields": "key"}
            )
            issues = (self._req("GET", f"/rest/api/3/search/jql?{q}") or {}).get("issues") or []
            if issues:
                k = str(issues[0]["key"])
                return Delivered(k, f"{self.base_url.rstrip('/')}/browse/{k}", created=False)
            return None
        q = urllib.parse.urlencode({"sysparm_query": f"correlation_id={key}", "sysparm_limit": 1,
                                    "sysparm_fields": "sys_id,number"})  # fmt: skip
        rows = (self._req("GET", f"/api/now/table/{self.servicenow_table}?{q}") or {}).get("result")
        if rows:
            return Delivered(str(rows[0].get("number") or rows[0]["sys_id"]), None, created=False)
        return None

    def create(self, rendered: dict[str, Any]) -> Delivered:
        if self.target == "jira":
            out = self._req("POST", "/rest/api/3/issue", rendered)
            k = str(out.get("key") or "")
            if not k:
                raise DeliveryError("ITSM_BAD_RESPONSE", retryable=True)
            return Delivered(k, f"{self.base_url.rstrip('/')}/browse/{k}", created=True)
        out = (self._req("POST", f"/api/now/table/{self.servicenow_table}", rendered) or {}).get(
            "result"
        ) or {}
        ref = str(out.get("number") or out.get("sys_id") or "")
        if not ref:
            raise DeliveryError("ITSM_BAD_RESPONSE", retryable=True)
        return Delivered(ref, None, created=True)

    def deliver(self, outbox_id: str, rendered: dict[str, Any]) -> Delivered:
        return self.find(outbox_id) or self.create(rendered)


def client_from_settings(s: Settings) -> ItsmClient:
    if not (s.itsm_target and s.itsm_base_url and s.itsm_username and s.itsm_token):
        raise DeliveryError("ITSM_NOT_CONFIGURED", retryable=False)
    return ItsmClient(
        target=s.itsm_target, base_url=s.itsm_base_url, username=s.itsm_username,
        token=s.itsm_token.get_secret_value(), timeout=float(s.itsm_timeout_seconds),
        servicenow_table=s.itsm_servicenow_table,
    )  # fmt: skip
