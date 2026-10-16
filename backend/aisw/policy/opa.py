"""OPA policy engine (ADR-003, ADR-031): the packaged Rego, evaluated by an OPA server over HTTP.

The server must run exactly the Rego shipped in ``aisw/policy/rego`` (tests excluded); the
evaluator compares a hash of the sources the server reports with the packaged ones before use
and refuses to start on a mismatch. A server that cannot be reached raises, so the task retries
instead of recording outcomes nobody evaluated.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Callable, Mapping
from importlib import resources
from typing import Any

from aisw.contracts.enums import PolicyOutcome
from aisw.core import safe_http
from aisw.policy.engine import PackRule, PolicyPack

MAX_RESPONSE = 1 << 20

Fetch = Callable[[urllib.request.Request, float, int], bytes]


class OpaError(Exception):
    pass


def rego_sources() -> dict[str, str]:
    """Packaged policy modules by relative path, without the ``*_test.rego`` unit tests."""
    root = resources.files("aisw.policy") / "rego"
    out: dict[str, str] = {}

    def walk(node: Any, prefix: str) -> None:
        for entry in node.iterdir():
            name = f"{prefix}{entry.name}"
            if entry.is_dir():
                walk(entry, f"{name}/")
            elif name.endswith(".rego") and not name.endswith("_test.rego"):
                out[name] = entry.read_text(encoding="utf-8")

    walk(root, "")
    return out


def sources_hash(sources: Mapping[str, str] | list[str]) -> str:
    texts = sorted(sources.values() if isinstance(sources, Mapping) else sources)
    return "sha256:" + hashlib.sha256("\0".join(texts).encode()).hexdigest()


def bundle_hash() -> str:
    return sources_hash(rego_sources())


def _default_fetch(req: urllib.request.Request, timeout: float, max_bytes: int) -> bytes:
    try:
        return safe_http.fetch(req, timeout=timeout, max_bytes=max_bytes)
    except safe_http.HttpError as exc:
        raise OpaError(f"opa {req.get_method()} {req.full_url}: {exc}") from None


class OpaClient:
    def __init__(self, url: str, *, timeout: float = 5.0, fetch: Fetch | None = None) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._fetch = fetch or _default_fetch

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        req = urllib.request.Request(  # noqa: S310
            f"{self.url}{path}", data=data, method=method,
            headers={"content-type": "application/json", "accept": "application/json"},
        )  # fmt: skip
        try:
            return json.loads(self._fetch(req, self.timeout, MAX_RESPONSE))
        except (OSError, ValueError) as exc:
            raise OpaError(f"opa {method} {path}: {exc}") from None

    def query(self, rule: str, input_doc: Mapping[str, Any]) -> Any:
        """Value of ``data.<rule>`` for this input, or None when it is undefined."""
        reply = self._call("POST", f"/v1/data/{rule.replace('.', '/')}", {"input": input_doc})
        return reply.get("result") if isinstance(reply, dict) else None

    def policies_hash(self) -> str:
        reply = self._call("GET", "/v1/policies")
        mods = reply.get("result") if isinstance(reply, dict) else None
        if not isinstance(mods, list):
            raise OpaError("opa /v1/policies: unexpected reply")
        return sources_hash(
            [m["raw"] for m in mods if not str(m.get("id", "")).endswith("_test.rego")]
        )


def _attrs(attrs: Mapping[str, Any]) -> dict[str, str]:
    """Stringified like ``PackRule.applies`` does, so both engines decide applicability alike."""
    return {k: str(v) for k, v in attrs.items()}


def _rule_doc(rule: PackRule) -> dict[str, Any]:
    return rule.model_dump(mode="json", include={"rule_id", "applies_to", "check"})


class OpaEvaluator:
    runs_rego = True

    def __init__(self, client: OpaClient, *, verify: bool = True) -> None:
        self.client = client
        if verify:
            served, packaged = client.policies_hash(), bundle_hash()
            if served != packaged:
                raise OpaError(
                    f"OPA serves policy {served}, this build ships {packaged}; refusing to evaluate"
                )

    def applicable_rules(self, pack: PolicyPack, attrs: Mapping[str, Any]) -> list[PackRule]:
        ids = self.client.query(
            "aisw.policy.applicable",
            {"rules": [_rule_doc(r) for r in pack.rules], "attrs": _attrs(attrs)},
        )
        if not isinstance(ids, list):
            raise OpaError("opa applicable: undefined")
        wanted = set(ids)
        return [r for r in pack.rules if r.rule_id in wanted]

    def evaluate_observation(
        self, pack: PolicyPack, *, rule_id: str, value: Any, attrs: Mapping[str, Any]
    ) -> PolicyOutcome | None:
        rule = pack.rule(rule_id)
        if rule is None:
            return None
        try:
            doc = {"rule": _rule_doc(rule), "value": value, "attrs": _attrs(attrs)}
            json.dumps(doc, allow_nan=False)
        except ValueError:
            return PolicyOutcome.ERROR  # NaN/Infinity: the check cannot run on this value
        decision = self.client.query("aisw.policy.decision", doc)
        if not isinstance(decision, dict):
            raise OpaError("opa decision: undefined")
        if not decision.get("applies"):
            return None
        return PolicyOutcome(decision["outcome"])
