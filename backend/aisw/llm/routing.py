"""Composable model-client wrappers (ADR-023): metering, failover, record/replay, run budgets.

Every wrapper is itself a ModelClient, so the gateways stay unaware of routing. None of them adds a
tool parameter, changes a prompt or relaxes grounding: they only decide whether and where a call
is made, and record what it cost.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Literal

from aisw.llm.client import ModelClient, ModelUnavailable, Usage, complete_with_usage

# Worth trying another deployment for: the service, not the request, was the problem.
TRANSIENT = frozenset(
    {"MODEL_UNREACHABLE", "MODEL_RATE_LIMITED", "MODEL_TIMEOUT", "MODEL_RESPONSE_INCOMPLETE"}
)


class CallMeter:
    """Wraps one gateway call (all its attempts) and totals what it cost."""

    def __init__(self, client: ModelClient, clock: Callable[[], float] = time.monotonic) -> None:
        self._client, self._clock = client, clock
        self.input_tokens: int | None = None
        self.output_tokens: int | None = None
        self.latency_ms = 0
        self.served_by: str | None = None
        self.replayed = False

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        start = self._clock()
        try:
            text, usage = complete_with_usage(
                self._client, system=system, user=user, schema=schema, timeout=timeout
            )
        finally:
            self.latency_ms += max(0, round((self._clock() - start) * 1000))
        self.served_by, self.replayed = usage.model_id, usage.replayed
        for name in ("input_tokens", "output_tokens"):
            if (n := getattr(usage, name)) is not None:
                setattr(self, name, (getattr(self, name) or 0) + n)
        return text

    def provenance(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
            "latency_ms": self.latency_ms, "replayed": self.replayed,
            **({"model_id": self.served_by} if self.served_by else {}),
        }  # fmt: skip


class FailoverClient:
    """Tries deployments in order. A deployment that fails transiently is skipped for ``cooldown``
    seconds (unless every deployment is cooling down); any other failure is final for the call."""

    def __init__(
        self, clients: Sequence[ModelClient], *, cooldown: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:  # fmt: skip
        if not clients:
            raise ValueError("at least one model client is required")
        self._clients, self._cooldown, self._clock = list(clients), cooldown, clock
        self._until: dict[int, float] = {}
        self._lock = threading.Lock()

    @property
    def model_id(self) -> str | None:
        return self._clients[0].model_id

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        return self.complete_with_usage(system=system, user=user, schema=schema, timeout=timeout)[0]

    def complete_with_usage(
        self, *, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> tuple[str, Usage]:
        now = self._clock()
        with self._lock:
            ready = [i for i in range(len(self._clients)) if self._until.get(i, 0.0) <= now]
        last = ModelUnavailable("MODEL_UNREACHABLE")
        for i in ready or range(len(self._clients)):
            try:
                result = complete_with_usage(
                    self._clients[i], system=system, user=user, schema=schema, timeout=timeout
                )
            except ModelUnavailable as exc:
                if exc.code not in TRANSIENT:
                    raise
                with self._lock:
                    self._until[i] = self._clock() + self._cooldown
                last = exc
                continue
            with self._lock:
                self._until.pop(i, None)
            return result
        raise last


ReplayMode = Literal["record", "replay"]


_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


_PLACEHOLDER = re.compile(r"<id(\d+)>")


def _numbering(user: str) -> dict[str, str]:
    seen: dict[str, str] = {}
    for m in _UUID.finditer(user):
        seen.setdefault(m[0], f"<id{len(seen)}>")
    return seen


def replay_key(model_id: str | None, system: str, user: str, schema: dict[str, Any]) -> str:
    """Identifiers minted per run (UUIDs) are numbered by first appearance, so the same inputs
    replay across runs. A replayed reply is still grounded against the current run."""
    seen = _numbering(user)
    user = _UUID.sub(lambda m: seen[m[0]], user)
    blob = json.dumps({"m": model_id, "s": system, "u": user, "j": schema}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _to_placeholders(text: str, user: str) -> str:
    seen = _numbering(user)
    return _UUID.sub(lambda m: seen.get(m[0], m[0]), text)


def _from_placeholders(text: str, user: str) -> str:
    ids = list(_numbering(user))
    return _PLACEHOLDER.sub(lambda m: ids[int(m[1])] if int(m[1]) < len(ids) else m[0], text)


class RecordReplayClient:
    """``record`` stores each successful reply under a hash of the exact request; ``replay`` answers
    only from that store and never reaches a network (a miss is ``REPLAY_MISS``). Prompts are not
    stored, only their hash and the reply; run identifiers in the reply are stored as the
    prompt's placeholders and restored to the replaying run's identifiers."""

    def __init__(
        self, inner: ModelClient | None, directory: Path, mode: ReplayMode, *,
        model_id: str | None = None,
    ) -> None:  # fmt: skip
        if mode == "record" and inner is None:
            raise ValueError("record mode needs a model client to record from")
        self._inner, self._dir, self._mode = inner, directory, mode
        self.model_id = model_id if inner is None else inner.model_id
        if mode == "record":
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        return self.complete_with_usage(system=system, user=user, schema=schema, timeout=timeout)[0]

    def complete_with_usage(
        self, *, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> tuple[str, Usage]:
        path = self._dir / f"{replay_key(self.model_id, system, user, schema)}.json"
        if self._mode == "replay":
            try:
                doc = json.loads(path.read_text())
                return _from_placeholders(str(doc["text"]), user), Usage(
                    doc.get("model_id"), doc.get("input_tokens"), doc.get("output_tokens"),
                    replayed=True,
                )  # fmt: skip
            except (OSError, ValueError, KeyError, TypeError):
                raise ModelUnavailable("REPLAY_MISS") from None
        if self._inner is None:  # unreachable: record mode refuses a missing client
            raise ModelUnavailable("REPLAY_MISS")
        text, usage = complete_with_usage(
            self._inner, system=system, user=user, schema=schema, timeout=timeout
        )
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"model_id": usage.model_id, "text": _to_placeholders(text, user),
                       "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens}, f)  # fmt: skip
        os.replace(tmp, path)
        return text, usage


def estimate_tokens(*texts: str) -> int:
    """Rough and deliberately high (about 4 characters per token, rounded up)."""
    return sum(-(-len(t) // 4) for t in texts)


class TokenBudget:
    """One run's token allowance, shared by every concurrent call the run makes."""

    def __init__(self, limit: int, used: int = 0) -> None:
        self.limit, self.used = limit, used
        self.refused = 0
        self._lock = threading.Lock()

    def reserve(self, estimate: int) -> None:
        with self._lock:
            if self.used + estimate > self.limit:
                self.refused += 1
                raise ModelUnavailable("MODEL_BUDGET_EXHAUSTED")
            self.used += estimate

    def settle(self, estimate: int, actual: int) -> None:
        with self._lock:
            self.used += actual - estimate


class BudgetedClient:
    """Refuses a call whose prompt alone would exceed the run's remaining tokens; charges what a
    call actually reported (or the estimate when the provider did not say). Replays are free."""

    def __init__(self, inner: ModelClient, budget: TokenBudget) -> None:
        self._inner, self._budget = inner, budget
        self.model_id = inner.model_id

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        return self.complete_with_usage(system=system, user=user, schema=schema, timeout=timeout)[0]

    def complete_with_usage(
        self, *, system: str, user: str, schema: dict[str, Any], timeout: float
    ) -> tuple[str, Usage]:
        estimate = estimate_tokens(system, user)
        self._budget.reserve(estimate)
        try:
            text, usage = complete_with_usage(
                self._inner, system=system, user=user, schema=schema, timeout=timeout
            )
        except ModelUnavailable:
            self._budget.settle(estimate, 0)
            raise
        if usage.replayed:
            actual = 0
        elif usage.input_tokens is not None and usage.output_tokens is not None:
            actual = usage.input_tokens + usage.output_tokens
        else:
            actual = estimate + estimate_tokens(text)
        self._budget.settle(estimate, actual)
        return text, usage
