"""Labelled-set evaluation of the AI reviewer and the narrative grounding validator (ADR-025).

The set is synthetic and versioned. Each review case is one validation target with a label: CLEAN
(a careful reviewer concurs) or DEFECT (a planted error a careful reviewer flags). Cases go through
the production ``ValidationGateway`` and ``LlmGateway`` unchanged, so what is measured is exactly
what a run would do. Numbers come only from calls actually made; nothing is estimated.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from aisw.agents.registry import AGENTS
from aisw.contracts.base import NonEmpty, StrictModel
from aisw.llm.client import ModelClient
from aisw.llm.gateway import PROMPT_VERSION as NARRATIVE_PROMPT
from aisw.llm.gateway import LlmGateway
from aisw.llm.packets import FOCUS
from aisw.llm.schema import NarrativeSubject
from aisw.llm.validation import PROMPT_VERSION as VALIDATION_PROMPT
from aisw.llm.validation import ValidationGateway, ValidationPacket, ValidationTarget

DEFAULT_SET = "labelled-1.0.0"
FLAGGED = frozenset({"CONCERN", "DISSENT"})

# Provisional acceptance bar until the policy owner signs one off (pending plan P0-6).
MIN_RECALL = 0.7
MAX_FALSE_DISSENT = 0.1
MAX_UNSCORED = 0.1


class ReviewCase(StrictModel):
    case_id: NonEmpty
    agent_id: int = Field(ge=0, le=8)
    label: Literal["CLEAN", "DEFECT"]
    expect: NonEmpty
    target: ValidationTarget


class NarrationCase(StrictModel):
    case_id: NonEmpty
    subject: NarrativeSubject


class LabelledSet(StrictModel):
    version: NonEmpty
    note: NonEmpty
    review: list[ReviewCase] = Field(min_length=1)
    narration: list[NarrationCase] = Field(default_factory=list)


class ReviewRow(StrictModel):
    case_id: str
    agent_id: int
    label: str
    verdict: str | None  # None when the packet's reply was invalid or unavailable
    issue_codes: list[str]
    explanations: list[str] = Field(default_factory=list)
    packet_status: str
    packet_defects: list[str] = Field(default_factory=list)


class NarrationRow(StrictModel):
    case_id: str
    purpose: str
    status: str
    defects: list[str]
    attempts: int


class EvaluationReport(StrictModel):
    set_version: str
    generated_at: str
    model_id: str | None
    served_by: list[str]
    prompt_versions: dict[str, str]
    review: list[ReviewRow]
    narration: list[NarrationRow]
    metrics: dict[str, Any]
    decision: Literal["USABLE", "NOT_USABLE", "INCONCLUSIVE"]
    reasons: list[str]


def load_labelled_set(path: Path | None = None, version: str = DEFAULT_SET) -> LabelledSet:
    if path is not None:
        raw = path.read_text()
    else:
        raw = (resources.files("aisw.llm") / "eval_data" / f"{version}.json").read_text()
    ls = LabelledSet.model_validate_json(raw)
    ids = [c.case_id for c in ls.review] + [c.case_id for c in ls.narration]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case_id in labelled set")
    return ls


def review_packets(ls: LabelledSet) -> list[tuple[ValidationPacket, list[ReviewCase]]]:
    """One packet per agent, in agent order, exactly as the pipeline would batch them."""
    out = []
    for agent in AGENTS:
        cases = [c for c in ls.review if c.agent_id == agent.agent_id]
        if cases:
            packet = ValidationPacket(
                packet_id=f"eval-a{agent.agent_id}", agent_id=agent.agent_id,
                agent_name=agent.name, focus=FOCUS[agent.agent_id],
                targets=[c.target for c in cases],
            )  # fmt: skip
            out.append((packet, cases))
    return out


def _rate(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def score(review: list[ReviewRow], narration: list[NarrationRow]) -> dict[str, Any]:
    scored = [r for r in review if r.verdict is not None]
    defect = [r for r in scored if r.label == "DEFECT"]
    clean = [r for r in scored if r.label == "CLEAN"]
    by_agent: dict[str, dict[str, int]] = {}
    for r in review:
        slot = by_agent.setdefault(str(r.agent_id), {"cases": 0, "detected": 0, "false_flags": 0})
        slot["cases"] += 1
        flagged = r.verdict in FLAGGED
        slot["detected"] += r.label == "DEFECT" and flagged
        slot["false_flags"] += r.label == "CLEAN" and flagged
    validated = sum(n.status == "VALIDATED" for n in narration)
    return {
        "review_cases": len(review),
        "unscored": len(review) - len(scored),
        "unscored_rate": _rate(len(review) - len(scored), len(review)),
        "defect_cases": len(defect),
        "clean_cases": len(clean),
        "detected": sum(r.verdict in FLAGGED for r in defect),
        "dissented_on_defect": sum(r.verdict == "DISSENT" for r in defect),
        "recall": _rate(sum(r.verdict in FLAGGED for r in defect), len(defect)),
        "false_flag_rate": _rate(sum(r.verdict in FLAGGED for r in clean), len(clean)),
        "false_dissent_rate": _rate(sum(r.verdict == "DISSENT" for r in clean), len(clean)),
        "insufficient_evidence": sum(r.verdict == "INSUFFICIENT_EVIDENCE" for r in scored),
        "by_agent": by_agent,
        "narration_cases": len(narration),
        "narration_validated": validated,
        "narration_rejection_rate": _rate(
            sum(n.status == "REJECTED" for n in narration), len(narration)
        ),
        "narration_unavailable": sum(n.status == "UNAVAILABLE" for n in narration),
        "narration_defects": dict(Counter(d.split(":")[0] for n in narration for d in n.defects)),
    }


def decide(m: dict[str, Any]) -> tuple[Literal["USABLE", "NOT_USABLE", "INCONCLUSIVE"], list[str]]:
    reasons: list[str] = []
    if m["unscored_rate"] is None or m["unscored_rate"] > MAX_UNSCORED:
        reasons.append(f"unscored rate {m['unscored_rate']} exceeds {MAX_UNSCORED}")
        return "INCONCLUSIVE", reasons
    if m["recall"] is None or m["recall"] < MIN_RECALL:
        reasons.append(f"recall {m['recall']} below {MIN_RECALL}")
    if m["false_dissent_rate"] is not None and m["false_dissent_rate"] > MAX_FALSE_DISSENT:
        reasons.append(f"false dissent rate {m['false_dissent_rate']} above {MAX_FALSE_DISSENT}")
    return ("NOT_USABLE" if reasons else "USABLE"), reasons


def evaluate(
    ls: LabelledSet, generator: ModelClient | None, reviewer: ModelClient, *,
    timeout: float = 60.0, now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> EvaluationReport:  # fmt: skip
    served: set[str] = set()
    review: list[ReviewRow] = []
    vgw = ValidationGateway(reviewer, timeout=timeout)
    for packet, cases in review_packets(ls):
        res = vgw.validate(packet)
        if res.model_id:
            served.add(res.model_id)
        verdicts = {v.target_ref: v for v in res.output.verdicts} if res.output else {}
        for c in cases:
            v = verdicts.get(c.target.target_ref)
            review.append(ReviewRow(
                case_id=c.case_id, agent_id=c.agent_id, label=c.label,
                verdict=v.verdict if v else None,
                issue_codes=[i.code for i in v.issues] if v else [],
                explanations=[i.explanation for i in v.issues] if v else [],
                packet_status=res.status, packet_defects=res.defects,
            ))  # fmt: skip
    narration: list[NarrationRow] = []
    if generator is not None:
        ngw = LlmGateway(generator, timeout=timeout)
        for n in ls.narration:
            nres = ngw.narrate(n.subject)
            if nres.model_id:
                served.add(nres.model_id)
            narration.append(NarrationRow(
                case_id=n.case_id, purpose=n.subject.purpose, status=nres.status,
                defects=nres.defects, attempts=nres.attempts,
            ))  # fmt: skip
    metrics = score(review, narration)
    decision, reasons = decide(metrics)
    return EvaluationReport(
        set_version=ls.version, generated_at=now().isoformat(), model_id=reviewer.model_id,
        served_by=sorted(served),
        prompt_versions={"validation": VALIDATION_PROMPT, "narrative": NARRATIVE_PROMPT},
        review=review, narration=narration, metrics=metrics, decision=decision, reasons=reasons,
    )  # fmt: skip


def render_markdown(rep: EvaluationReport) -> str:
    m = rep.metrics
    lines = [
        f"# AI evaluation on `{rep.set_version}` ({rep.generated_at[:10]})", "",
        "Synthetic labelled set only. Numbers are produced by `tools/eval_labelled.py` from the calls "
        "it made; they are not edited by hand.", "",
        f"- Reviewer model: `{rep.model_id}`; replies served by: "
        f"{', '.join(f'`{s}`' for s in rep.served_by) or 'none'}",
        f"- Prompts: validation `{rep.prompt_versions['validation']}`, narrative "
        f"`{rep.prompt_versions['narrative']}`",
        f"- **Decision: {rep.decision}**" + (f" ({'; '.join(rep.reasons)})" if rep.reasons else ""),
        "", "## Reviewer", "",
        f"- Planted defects flagged (CONCERN or DISSENT): {m['detected']} of {m['defect_cases']} "
        f"(recall {m['recall']}); dissents on defects: {m['dissented_on_defect']}",
        f"- Clean cases flagged: false-flag rate {m['false_flag_rate']}, false-dissent rate "
        f"{m['false_dissent_rate']} over {m['clean_cases']} clean cases",
        f"- Unscored (reply invalid or unavailable): {m['unscored']} of {m['review_cases']}", "",
        "| Case | Agent | Label | Verdict | Issue codes |", "|---|---|---|---|---|",
        *(f"| {r.case_id} | {r.agent_id} | {r.label} | "
          f"{r.verdict or ' '.join([r.packet_status, *r.packet_defects])} | "
          f"{', '.join(r.issue_codes) or '-'} |" for r in rep.review),
        "", "## Narration grounding", "",
        f"- Validated {m['narration_validated']} of {m['narration_cases']}; rejection rate "
        f"{m['narration_rejection_rate']}; unavailable {m['narration_unavailable']}",
        f"- Rejection defects: {json.dumps(m['narration_defects'], sort_keys=True)}", "",
        "| Case | Purpose | Status | Defects | Attempts |", "|---|---|---|---|---|",
        *(f"| {n.case_id} | {n.purpose} | {n.status} | {', '.join(n.defects) or '-'} | "
          f"{n.attempts} |" for n in rep.narration),
        "", f"Acceptance bar (provisional until a policy owner signs one off): recall >= "
        f"{MIN_RECALL}, false-dissent rate <= {MAX_FALSE_DISSENT}, unscored <= {MAX_UNSCORED}.", "",
    ]  # fmt: skip
    return "\n".join(lines)
