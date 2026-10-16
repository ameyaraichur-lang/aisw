"""Scripted stand-in for a model. No weights, no network: it returns what the test tells it to."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from aisw.llm.client import ModelUnavailable
from aisw.llm.schema import NarrativeSubject

Step = str | Exception | Callable[[str, str], str]


class ScriptedModel:
    model_id = "stub-model-0"

    def __init__(self, *steps: Step) -> None:
        self._steps = list(steps)
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        self.calls.append({"system": system, "user": user, "schema": schema, "timeout": timeout})
        step = self._steps.pop(0) if len(self._steps) > 1 else self._steps[0]
        if isinstance(step, Exception):
            raise step
        return step(system, user) if callable(step) else step


def good_output(subject: NarrativeSubject, **overrides: Any) -> str:
    f = subject.facts[0]
    body: dict[str, Any] = {
        "summary": f"{len(subject.facts)} recorded weaknesses relate to {f.asset_ids[0]}.",
        "claims": [
            {
                "text": f"The assessment recorded: {f.title}.",
                "finding_ids": [f.finding_id],
                "asset_ids": [f.asset_ids[0]],
            }
        ],
        "open_questions": (
            [f"Is the exposure recorded for {f.asset_ids[0]} intended?"]
            if subject.purpose == "verification" else []
        ),
    }  # fmt: skip
    body.update(overrides)
    return json.dumps(body)


def echo_first_fact(subject: NarrativeSubject) -> Step:
    return lambda _s, _u: good_output(subject)


OUTAGE = ModelUnavailable("MODEL_UNREACHABLE")
