"""Model-call routing (ADR-023): metering, failover, record/replay and run budgets. No network."""

from __future__ import annotations

import json
import stat
import threading
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from aisw.core.config import Settings
from aisw.llm.client import (
    AstraClient,
    DisabledModelClient,
    ModelUnavailable,
    OllamaClient,
    Usage,
    complete_with_usage,
)
from aisw.llm.factory import build_model_client, build_validation_client
from aisw.llm.gateway import LlmGateway
from aisw.llm.routing import (
    BudgetedClient,
    CallMeter,
    FailoverClient,
    RecordReplayClient,
    TokenBudget,
    estimate_tokens,
    replay_key,
)
from tests.evaluation.conftest import make_subject
from tests.evaluation.stub import good_output
from tests.evaluation.test_astra_client import (
    ENDPOINT,
    FAKE_KEY,
    FakeOpener,
    http_error,
    message,
    response,
)

KW: dict[str, Any] = {"system": "sys", "user": "DATA:\n{}", "schema": {}, "timeout": 1.0}


class Fake:
    """A metered client answering from a script of (text | exception) with fixed usage."""

    def __init__(self, model_id: str, *steps: str | Exception, tokens: tuple[int, int] = (10, 5)):
        self.model_id, self.steps, self.tokens, self.calls = model_id, list(steps), tokens, 0

    def complete(self, **kw: Any) -> str:
        return self.complete_with_usage(**kw)[0]

    def complete_with_usage(self, **_: Any) -> tuple[str, Usage]:
        self.calls += 1
        step = self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]
        if isinstance(step, Exception):
            raise step
        return step, Usage(self.model_id, *self.tokens)


class Plain:
    model_id = "plain-0"

    def complete(self, **_: Any) -> str:
        return "ok"


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def down(code: str = "MODEL_UNREACHABLE") -> ModelUnavailable:
    return ModelUnavailable(code)


# ---- usage reporting --------------------------------------------------------------------------
def test_a_client_without_usage_is_metered_as_unknown() -> None:
    assert complete_with_usage(Plain(), **KW) == ("ok", Usage("plain-0"))


def test_astra_reports_tokens_from_the_responses_api() -> None:
    body = json.loads(response(message("hi")))
    body["usage"] = {"input_tokens": 120, "output_tokens": 34, "total_tokens": 154}
    c = AstraClient(ENDPOINT, "gpt-astra", SecretStr(FAKE_KEY), api_version="2025-04-01-preview",
                    opener=FakeOpener(json.dumps(body).encode()))  # fmt: skip
    assert c.complete_with_usage(**KW) == ("hi", Usage("gpt-astra", 120, 34))


@pytest.mark.parametrize("usage", [None, {"input_tokens": -1, "output_tokens": "9"}, [], True])
def test_astra_ignores_missing_or_bogus_usage(usage: Any) -> None:
    body = {"id": "r", "status": "completed", "output": [message("hi")], "usage": usage}
    c = AstraClient(ENDPOINT, "gpt-astra", SecretStr(FAKE_KEY), api_version="2025-04-01-preview",
                    opener=FakeOpener(json.dumps(body).encode()))  # fmt: skip
    assert c.complete_with_usage(**KW) == ("hi", Usage("gpt-astra", None, None))


def test_ollama_reports_eval_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    c = OllamaClient("http://127.0.0.1:1", "m-0")
    doc = {"message": {"content": "hi"}, "prompt_eval_count": 7, "eval_count": 3}

    class R:
        def __enter__(self) -> R:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self, _n: int) -> bytes:
            return json.dumps(doc).encode()

    monkeypatch.setattr(c._opener, "open", lambda *a, **k: R())
    assert c.complete_with_usage(**KW) == ("hi", Usage("m-0", 7, 3))


def test_meter_totals_every_attempt_and_names_who_served() -> None:
    clock = Clock()

    class Slow(Fake):
        def complete_with_usage(self, **kw: Any) -> tuple[str, Usage]:
            clock.t += 0.25
            return super().complete_with_usage(**kw)

    m = CallMeter(Slow("dep-b", down(), "a", "b"), clock=clock)
    with pytest.raises(ModelUnavailable):
        m.complete(**KW)
    m.complete(**KW)
    m.complete(**KW)
    assert m.provenance() == {"input_tokens": 20, "output_tokens": 10, "latency_ms": 750,
                              "replayed": False, "model_id": "dep-b"}  # fmt: skip


def test_gateway_records_usage_and_the_serving_deployment() -> None:
    subject = make_subject()
    res = LlmGateway(Fake("fallback-dep", good_output(subject), tokens=(300, 40))).narrate(subject)
    assert res.status == "VALIDATED"
    assert (res.model_id, res.input_tokens, res.output_tokens) == ("fallback-dep", 300, 40)
    assert res.latency_ms >= 0 and not res.replayed


# ---- failover ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "code",
    ["MODEL_UNREACHABLE", "MODEL_RATE_LIMITED", "MODEL_TIMEOUT", "MODEL_RESPONSE_INCOMPLETE"],
)
def test_a_transient_failure_fails_over_to_the_next_deployment(code: str) -> None:
    a, b = Fake("a", down(code)), Fake("b", "from-b")
    f = FailoverClient([a, b])
    assert f.model_id == "a"
    assert f.complete_with_usage(**KW) == ("from-b", Usage("b", 10, 5))


@pytest.mark.parametrize("code", ["MODEL_AUTH_FAILED", "MODEL_REFUSED", "MODEL_TOOL_CALL_REFUSED",
                                  "MODEL_RESPONSE_UNREADABLE", "MODEL_RESPONSE_TOO_LARGE"])  # fmt: skip
def test_a_request_level_failure_never_fails_over(code: str) -> None:
    a, b = Fake("a", down(code)), Fake("b", "from-b")
    with pytest.raises(ModelUnavailable) as e:
        FailoverClient([a, b]).complete(**KW)
    assert e.value.code == code and b.calls == 0


def test_a_failed_deployment_cools_down_and_is_retried_afterwards() -> None:
    clock = Clock()
    a, b = Fake("a", down(), "from-a"), Fake("b", "from-b")
    f = FailoverClient([a, b], cooldown=30, clock=clock)
    assert f.complete(**KW) == "from-b"
    assert f.complete(**KW) == "from-b" and a.calls == 1  # a is cooling down: not even tried
    clock.t = 31
    assert f.complete(**KW) == "from-a" and a.calls == 2


def test_when_everything_is_cooling_down_all_are_tried_and_the_last_error_is_raised() -> None:
    a, b = Fake("a", down("MODEL_TIMEOUT")), Fake("b", down("MODEL_RATE_LIMITED"))
    f = FailoverClient([a, b], cooldown=300)
    for _ in range(2):
        with pytest.raises(ModelUnavailable) as e:
            f.complete(**KW)
        assert e.value.code == "MODEL_RATE_LIMITED"
    assert (a.calls, b.calls) == (2, 2)


def test_failover_needs_a_client() -> None:
    with pytest.raises(ValueError):
        FailoverClient([])


def test_real_astra_429_fails_over_through_the_factory() -> None:
    primary = AstraClient(ENDPOINT, "a", SecretStr(FAKE_KEY), api_version="v1",
                          opener=FakeOpener(http_error(429)))  # fmt: skip
    body = json.dumps({"status": "completed", "output": [message("ok")]}).encode()
    backup = AstraClient(ENDPOINT, "b", SecretStr(FAKE_KEY), api_version="v1",
                         opener=FakeOpener(body))  # fmt: skip
    assert FailoverClient([primary, backup]).complete_with_usage(**KW) == ("ok", Usage("b"))


# ---- record / replay --------------------------------------------------------------------------
def test_record_then_replay_answers_identically_without_a_model(tmp_path: Path) -> None:
    live = Fake("dep-a", "reply-1", tokens=(50, 9))
    rec = RecordReplayClient(live, tmp_path / "rec", "record")
    assert rec.complete_with_usage(**KW) == ("reply-1", Usage("dep-a", 50, 9))
    (f,) = (tmp_path / "rec").iterdir()
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert "DATA" not in f.read_text() and "sys" not in f.read_text()  # replies only, never prompts
    rep = RecordReplayClient(None, tmp_path / "rec", "replay", model_id="dep-a")
    assert rep.complete_with_usage(**KW) == ("reply-1", Usage("dep-a", 50, 9, replayed=True))
    assert live.calls == 1


def test_a_replay_miss_is_unavailable_and_not_retried(tmp_path: Path) -> None:
    rep = RecordReplayClient(None, tmp_path, "replay", model_id="dep-a")
    with pytest.raises(ModelUnavailable) as e:
        rep.complete(**KW)
    assert e.value.code == "REPLAY_MISS"
    subject = make_subject()
    res = LlmGateway(rep).narrate(subject)
    assert res.status == "UNAVAILABLE" and res.defects == ["REPLAY_MISS"] and res.attempts == 1


def test_replay_is_keyed_on_the_exact_request(tmp_path: Path) -> None:
    rec = RecordReplayClient(Fake("dep-a", "r"), tmp_path, "record")
    rec.complete(**KW)
    rep = RecordReplayClient(None, tmp_path, "replay", model_id="dep-a")
    with pytest.raises(ModelUnavailable):
        rep.complete(**{**KW, "user": 'DATA:\n{"x":1}'})
    other = RecordReplayClient(None, tmp_path, "replay", model_id="dep-b")
    with pytest.raises(ModelUnavailable):
        other.complete(**KW)
    assert replay_key("a", "s", "u", {}) != replay_key("a", "s", "u", {"x": 1})


def test_replay_keys_ignore_per_run_ids_but_not_their_structure() -> None:
    a, b, c = (f"{n}" * 8 + "-1111-2222-3333-444444444444" for n in "abc")
    k = replay_key("m", "s", f"ev://{a}/{b}/{a}", {})
    assert k == replay_key("m", "s", f"ev://{c}/{a}/{c}", {})
    assert k != replay_key("m", "s", f"ev://{a}/{b}/{b}", {})


def test_record_mode_needs_a_live_client(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        RecordReplayClient(None, tmp_path, "record")


# ---- budgets ----------------------------------------------------------------------------------
def test_budget_refuses_a_call_that_cannot_fit_and_is_not_retried() -> None:
    budget = TokenBudget(limit=estimate_tokens(KW["system"], KW["user"]) - 1)
    inner = Fake("a", "never")
    with pytest.raises(ModelUnavailable) as e:
        BudgetedClient(inner, budget).complete(**KW)
    assert e.value.code == "MODEL_BUDGET_EXHAUSTED" and inner.calls == 0 and budget.refused == 1
    subject = make_subject()
    res = LlmGateway(BudgetedClient(inner, budget)).narrate(subject)
    assert res.defects == ["MODEL_BUDGET_EXHAUSTED"] and res.attempts == 1


def test_budget_charges_reported_tokens_or_a_high_estimate() -> None:
    budget = TokenBudget(limit=1000, used=100)
    BudgetedClient(Fake("a", "x", tokens=(40, 2)), budget).complete(**KW)
    assert budget.used == 142

    class NoUsage(Fake):
        def complete_with_usage(self, **kw: Any) -> tuple[str, Usage]:
            text, _ = super().complete_with_usage(**kw)
            return text, Usage(self.model_id)

    BudgetedClient(NoUsage("a", "y" * 40), budget).complete(**KW)
    assert budget.used == 142 + estimate_tokens(KW["system"], KW["user"]) + 10


def test_budget_refunds_a_failed_call_and_replays_are_free(tmp_path: Path) -> None:
    budget = TokenBudget(limit=1000)
    with pytest.raises(ModelUnavailable):
        BudgetedClient(Fake("a", down()), budget).complete(**KW)
    assert budget.used == 0
    RecordReplayClient(Fake("a", "r"), tmp_path, "record").complete(**KW)
    replay = RecordReplayClient(None, tmp_path, "replay", model_id="a")
    BudgetedClient(replay, budget).complete(**KW)
    assert budget.used == 0


def test_budget_is_shared_safely_across_threads() -> None:
    per_call = estimate_tokens(KW["system"], KW["user"])
    budget = TokenBudget(limit=per_call * 5)

    class Est(Fake):  # reports exactly the reserved estimate, so 5 calls fit and no more
        def complete_with_usage(self, **kw: Any) -> tuple[str, Usage]:
            return "ok", Usage("a", per_call, 0)

    client = BudgetedClient(Est("a", "ok"), budget)
    ok, refused = [], []

    def call() -> None:
        try:
            client.complete(**KW)
            ok.append(1)
        except ModelUnavailable:
            refused.append(1)

    threads = [threading.Thread(target=call) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ok) == 5 and len(refused) == 15 and budget.used == per_call * 5


# ---- configuration and factory ----------------------------------------------------------------
ASTRA: dict[str, Any] = {
    "ai_enabled": True, "model_provider": "astra", "model_id": "gpt-6-astra",
    "astra_endpoint": ENDPOINT, "astra_api_key": FAKE_KEY, "astra_data_approval_ref": "DPA-1",
}  # fmt: skip


def test_fallbacks_build_a_failover_chain_and_the_reviewer_never_falls_back_to_the_writer() -> None:
    s = Settings(**ASTRA, astra_fallback_deployments="gpt-5.4,gpt-6-astra,gpt-4o",
                 astra_validation_deployment="gpt-5.4")  # fmt: skip
    gen = build_model_client(s)
    assert isinstance(gen, FailoverClient)
    assert [c.model_id for c in gen._clients] == ["gpt-6-astra", "gpt-5.4", "gpt-4o"]
    rev = build_validation_client(s)
    assert isinstance(rev, FailoverClient)
    assert [c.model_id for c in rev._clients] == ["gpt-5.4", "gpt-4o"]
    assert isinstance(build_model_client(Settings(**ASTRA)), AstraClient)


def test_replay_needs_no_key_and_never_builds_a_network_client(tmp_path: Path) -> None:
    s = Settings(env="test", ai_enabled=True, model_provider="astra", model_id="gpt-6-astra",
                 ai_replay_mode="replay", ai_replay_dir=tmp_path)  # fmt: skip
    c = build_model_client(s)
    assert isinstance(c, RecordReplayClient) and c._inner is None and c.model_id == "gpt-6-astra"


def test_record_wraps_the_live_client(tmp_path: Path) -> None:
    c = build_model_client(
        Settings(**ASTRA, env="test", ai_replay_mode="record", ai_replay_dir=tmp_path)
    )
    assert isinstance(c, RecordReplayClient) and isinstance(c._inner, AstraClient)


@pytest.mark.parametrize(
    "kw",
    [
        {"ai_replay_mode": "replay", "env": "test"},  # no directory
        {"ai_replay_mode": "replay", "ai_replay_dir": "replays"},  # default env is prod
        {"ai_replay_mode": "record", "ai_replay_dir": "replays", "env": "prod"},
        {"astra_fallback_deployments": "a,,b"},
        {"astra_fallback_deployments": "a;rm -rf"},
        {"ai_run_token_budget": -1},
    ],
)
def test_unsafe_routing_settings_are_refused(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Settings(**kw)


def test_ai_off_stays_disabled_whatever_the_routing() -> None:
    s = Settings(astra_fallback_deployments="a,b", ai_run_token_budget=0)
    assert isinstance(build_model_client(s), DisabledModelClient)
