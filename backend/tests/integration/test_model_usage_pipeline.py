"""Model-call usage, run budgets and record/replay (ADR-023) through the real API, Postgres and worker."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aisw.llm.client import Usage
from aisw.llm.routing import RecordReplayClient
from tests.evaluation.stub import ScriptedModel
from tests.integration.test_ai_validation_pipeline import ai_run, reviewer
from tests.integration.test_analysis_pipeline import shape
from tests.slice import Slice


class Metered(ScriptedModel):
    """The scripted reviewer, reporting usage like a real provider would."""

    model_id = "metered-0"

    def complete_with_usage(self, **kw: Any) -> tuple[str, Usage]:
        text = self.complete(**kw)
        return text, Usage(self.model_id, len(kw["user"]) // 4, len(text) // 4)


def concur() -> Metered:
    return Metered(reviewer(lambda _t: "CONCUR"))


def calls(sl: Slice, run_id: str) -> list[Any]:
    return sl.sql("SELECT purpose, model_id, input_tokens, output_tokens, latency_ms, replayed, "
                  "defects FROM llm_calls WHERE run_id=:r", r=run_id)  # fmt: skip


def test_every_call_records_tokens_latency_and_who_served_it(sl: Slice) -> None:
    _, run_id = ai_run(sl, concur())
    rows = calls(sl, run_id)
    assert rows and {p.split(":")[0] for p, *_ in rows} >= {"validation"}
    assert all(m == "metered-0" and i and o and lat >= 0 and not rp
               for _, m, i, o, lat, rp, _ in rows)  # fmt: skip

    ledger = sl.call("GET", f"/api/v1/assessments/{run_id}/model-calls", "carol")
    assert ledger.status_code == 200
    body = ledger.json()
    assert body["totals"]["calls"] == len(rows)
    assert body["totals"]["input_tokens"] == sum(r[2] for r in rows)
    assert body["totals"]["unmetered"] == 0 and body["totals"]["budget_refused"] == 0
    assert all("system" not in i and "user" not in i and "text" not in i for i in body["items"])
    assert sl.report(run_id)["ai"]["usage"]["calls"] == len(rows)
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/model-calls", "dave").status_code == 403
    assert sl.call("GET", "/api/v1/assessments/no-such-run/model-calls", "carol").status_code == 404


def test_the_run_budget_caps_live_tokens_and_the_report_says_so(sl: Slice) -> None:
    _, first = ai_run(sl, concur())
    spent = sum(i + o for _, _, i, o, *_ in calls(sl, first))

    sl.worker.run_token_budget = spent // 2
    _, run_id = ai_run(sl, concur())
    rows = calls(sl, run_id)
    refused = [r for r in rows if "MODEL_BUDGET_EXHAUSTED" in r[6]]
    assert refused and len(refused) < len(rows)
    assert sum((i or 0) + (o or 0) for _, _, i, o, *_ in rows) <= spent // 2
    rep = sl.report(run_id)
    assert rep["ai"]["usage"]["budget_refused"] == len(refused)
    assert any("token budget was exhausted" in x for x in rep["limitations"])


def test_an_exhausted_budget_never_calls_the_model_and_the_run_still_completes(sl: Slice) -> None:
    sl.worker.run_token_budget = 1
    model, run_id = ai_run(sl, concur())
    assert model.calls == []
    rows = calls(sl, run_id)
    assert rows and all("MODEL_BUDGET_EXHAUSTED" in r[6] for r in rows)
    assert sl.report(run_id)["coverage_complete"] is not None


def test_a_recorded_run_replays_identically_without_the_model(sl: Slice, tmp_path: Path) -> None:
    live = concur()
    _, recorded = ai_run(sl, RecordReplayClient(live, tmp_path, "record"))
    n_live = len(live.calls)
    assert n_live and len(list(tmp_path.iterdir())) > 0

    replay = RecordReplayClient(None, tmp_path, "replay", model_id="metered-0")
    _, replayed = ai_run(sl, replay)
    assert len(live.calls) == n_live  # nothing reached the model
    assert shape(sl.report(replayed)) == shape(sl.report(recorded))
    rows = calls(sl, replayed)
    assert rows and all(rp and not d for *_, rp, d in rows)
    rep = sl.report(replayed)
    assert rep["ai"]["usage"]["replayed"] == len(rows)
    assert any("replayed from a recording" in x for x in rep["limitations"])
    v = sl.sql("SELECT DISTINCT verdict FROM ai_validations WHERE run_id=:r", r=replayed)
    assert v == [("CONCUR",)]
