"""Run-level analysis phases (Agents 5, 6 and the assurance of their output).

Pure functions over a tenant-scoped connection, so the worker keeps ownership of transactions,
locking and state transitions. The model is NEVER called from here: pending narrative subjects are
returned to the worker, which calls the gateway outside the run-row lock.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Connection, text

from aisw.agents.architecture import Catalog, build_recommendations
from aisw.agents.assurance import (
    AssuranceContext,
    assess_narrative,
    assess_recommendation,
    assess_risk,
    assess_scenarios,
)
from aisw.agents.correlation import build_scenarios
from aisw.agents.registry import agent_for_adapter
from aisw.contracts.analysis import CorrelationScenario, RiskAssessment, RiskFactors
from aisw.contracts.assurance import AssuranceResult
from aisw.contracts.domain import CoverageLedger, Finding, Recommendation
from aisw.contracts.enums import AssuranceVerdict
from aisw.llm import packets as pk
from aisw.llm import triggers
from aisw.llm.gateway import NarrativeResult
from aisw.llm.schema import NarrativeOutput, NarrativeSubject
from aisw.llm.subject import (
    SEVERITY_ORDER,
    executive_subject,
    recommendation_subject,
    scenario_subject,
    verification_subject,
)
from aisw.llm.triggers import Decision as TriggerDecision
from aisw.llm.triggers import TriggerPolicy
from aisw.llm.validation import (
    ValidationPacket,
    ValidationResult,
    ValidationTarget,
    apply_dissent,
    effect_for,
)
from aisw.policy.results import finding_id_for
from aisw.policy.rubric import Rubric, assess, exposure_for, normalize_criticality


def load_findings(conn: Connection, run_id: str) -> dict[str, Finding]:
    rows = conn.execute(
        text("SELECT finding_id, body FROM findings WHERE run_id=:r ORDER BY finding_id"),
        {"r": run_id},
    ).all()
    return {fid: Finding.model_validate(b) for fid, b in rows}


def _asset_rows(
    conn: Connection, project: str, ids: set[str]
) -> dict[str, tuple[str | None, str | None]]:
    rows = conn.execute(
        text(
            "SELECT asset_id, owner, criticality FROM assets "
            "WHERE project_id=:p AND asset_id = ANY(:ids)"
        ),
        {"p": project, "ids": sorted(ids)},
    ).all()
    return {a: (o, c) for a, o, c in rows}


def _criticality(
    assets: list[str], rows: Mapping[str, tuple[str | None, str | None]], rubric: Rubric
) -> str | None:
    """Highest known label; UNKNOWN if ANY affected asset's label is missing or not a rubric label."""
    labels = [normalize_criticality((rows.get(a) or (None, None))[1], rubric) for a in assets]
    if not labels or any(label is None for label in labels):
        return None
    return max((x for x in labels if x), key=lambda x: rubric.criticality[x])


# ------------------------------------------------------------------ Agent 5 (+ risk rubric)
def correlation_phase(
    conn: Connection, run: dict[str, Any], *, rubric: Rubric, now: datetime, freshness: timedelta
) -> None:
    tenant, project, run_id = run["tenant_id"], str(run["project_id"]), run["run_id"]
    findings = load_findings(conn, run_id)
    if not findings:
        return
    assets = _asset_rows(conn, project, {a for f in findings.values() for a in f.affected_assets})
    collected: dict[str, datetime] = {
        ref: when
        for ref, when in conn.execute(
            text("SELECT evidence_ref, collected_at FROM evidence_artifacts WHERE run_id=:r"),
            {"r": run_id},
        )
    }
    sources: dict[str, int] = {
        a: int(n)
        for a, n in conn.execute(
            text(
                "SELECT s.asset_id, count(DISTINCT t.adapter_id) FROM run_asset_status s "
                "JOIN run_tasks t ON t.task_id = s.task_id WHERE s.run_id=:r AND s.status='SCANNED' "
                "GROUP BY s.asset_id"
            ),
            {"r": run_id},
        )
    }
    risks: dict[str, RiskAssessment] = {}
    for fid, f in findings.items():
        fresh = all(
            (when := collected.get(ref)) is not None and now - when <= freshness
            for ref in f.evidence_refs
        )
        factors = RiskFactors(
            severity=f.severity.value, criticality=_criticality(f.affected_assets, assets, rubric),
            exposure=exposure_for(f.category, rubric), evidence_fresh=fresh,
            corroborating_sources=max(1, min(sources.get(a, 1) for a in f.affected_assets)),
        )  # fmt: skip
        r = assess(fid, factors, rubric)
        risks[fid] = r
        conn.execute(
            text(
                "INSERT INTO risk_assessments (tenant_id, run_id, finding_id, rubric_version, tier, "
                "provisional_tier, basis, factors, missing_evidence, rationale) VALUES (:t, :r, :f, "
                ":v, :tier, :pt, :b, CAST(:fa AS jsonb), CAST(:m AS jsonb), :ra) ON CONFLICT DO NOTHING"
            ),
            {
                "t": tenant, "r": run_id, "f": fid, "v": r.rubric_version, "tier": r.tier,
                "pt": r.provisional_tier, "b": r.basis, "fa": json.dumps(r.factors.model_dump()),
                "m": json.dumps(r.missing_evidence), "ra": r.rationale,
            },
        )  # fmt: skip
    for s in build_scenarios(list(findings.values()), risks):
        conn.execute(
            text(
                "INSERT INTO correlation_scenarios (tenant_id, run_id, scenario_id, asset_id, body) "
                "VALUES (:t, :r, :s, :a, CAST(:b AS jsonb)) ON CONFLICT DO NOTHING"
            ),
            {"t": tenant, "r": run_id, "s": s.scenario_id, "a": s.asset_id,
             "b": json.dumps(s.model_dump(mode="json"))},
        )  # fmt: skip


def load_risks(conn: Connection, run_id: str) -> dict[str, RiskAssessment]:
    out: dict[str, RiskAssessment] = {}
    for fid, ver, tier, pt, basis, fac, miss, rat in conn.execute(
        text(
            "SELECT finding_id, rubric_version, tier, provisional_tier, basis, factors, "
            "missing_evidence, rationale FROM risk_assessments WHERE run_id=:r"
        ),
        {"r": run_id},
    ):  # fmt: skip
        out[fid] = RiskAssessment(
            finding_id=fid, rubric_version=ver, tier=tier, provisional_tier=pt, basis=basis,
            factors=RiskFactors.model_validate(fac), missing_evidence=miss, rationale=rat,
        )  # fmt: skip
    return out


def load_scenarios(conn: Connection, run_id: str) -> dict[str, CorrelationScenario]:
    rows = conn.execute(
        text(
            "SELECT scenario_id, body FROM correlation_scenarios WHERE run_id=:r ORDER BY scenario_id"
        ),
        {"r": run_id},
    ).all()
    return {sid: CorrelationScenario.model_validate(b) for sid, b in rows}


def load_recommendations(conn: Connection, run_id: str) -> dict[str, Recommendation]:
    rows = conn.execute(
        text(
            "SELECT recommendation_id, body FROM recommendations WHERE run_id=:r ORDER BY recommendation_id"
        ),
        {"r": run_id},
    ).all()
    return {rid: Recommendation.model_validate(b) for rid, b in rows}


# ------------------------------------------------------------------ Agent 6
def architecture_phase(
    conn: Connection,
    run: dict[str, Any],
    *,
    catalog: Catalog,
    scenario_ai: bool,
    recommendation_ai: bool,
    verification_ai: bool = False,
    executive_ai: bool = False,
) -> list[NarrativeSubject]:
    """Deterministic recommendations; returns the narrative subjects still missing (AI runs only)."""
    tenant, project, run_id = run["tenant_id"], str(run["project_id"]), run["run_id"]
    findings = load_findings(conn, run_id)
    risks = load_risks(conn, run_id)
    assets = _asset_rows(conn, project, {a for f in findings.values() for a in f.affected_assets})
    for r in build_recommendations(
        tenant_id=tenant, findings=list(findings.values()), risks=risks, assets=assets, catalog=catalog
    ):  # fmt: skip
        conn.execute(
            text(
                "INSERT INTO recommendations (tenant_id, run_id, recommendation_id, project_id, body) "
                "VALUES (:t, :r, :id, :p, CAST(:b AS jsonb)) ON CONFLICT DO NOTHING"
            ),
            {"t": tenant, "r": run_id, "id": r.recommendation_id, "p": project,
             "b": json.dumps(r.model_dump(mode="json"))},
        )  # fmt: skip
    if run["ai_mode"] != "enabled":
        return []
    done = {
        (p, s)
        for p, s in conn.execute(
            text("SELECT purpose, subject_ref FROM narratives WHERE run_id=:r"), {"r": run_id}
        )
    }
    pending: list[NarrativeSubject] = []
    if scenario_ai:
        for sid, s in load_scenarios(conn, run_id).items():
            if ("scenario", sid) not in done:
                pending.append(scenario_subject(s, findings))
    if recommendation_ai:
        for rid, rec in load_recommendations(conn, run_id).items():
            if ("recommendation", rid) not in done:
                pending.append(recommendation_subject(rec, findings))
    if verification_ai:
        pending += [s for s in verification_subjects(conn, run_id)
                    if ("verification", s.subject_ref) not in done]  # fmt: skip
    if (
        executive_ai
        and ("executive", "executive") not in done
        and (ex := executive_subject(findings.values(), load_ledgers(conn, run_id))) is not None
    ):
        pending.append(ex)
    return pending


def store_narratives(
    conn: Connection,
    run: dict[str, Any],
    results: list[tuple[NarrativeSubject, NarrativeResult]],
    now: datetime,
) -> None:
    for subject, res in results:
        n = conn.execute(
            text(
                "INSERT INTO narratives (tenant_id, run_id, narrative_id, purpose, subject_ref, status, "
                "body, defects, model_id, prompt_version, input_hash, output_hash, created_at) VALUES "
                "(:t, :r, :id, :p, :s, :st, CAST(:b AS jsonb), CAST(:d AS jsonb), :m, :pv, :ih, :oh, :n) "
                "ON CONFLICT DO NOTHING"
            ),
            {
                "t": run["tenant_id"], "r": run["run_id"], "id": f"nar-{subject.purpose}-{subject.subject_ref}",
                "p": subject.purpose, "s": subject.subject_ref, "st": res.status,
                "b": json.dumps({"output": res.output.model_dump(mode="json") if res.output else None,
                                 "input_flags": res.input_flags}),
                "d": json.dumps(res.defects), "m": res.model_id, "pv": res.prompt_version,
                "ih": res.input_hash, "oh": res.output_hash, "n": now,
            },
        ).rowcount  # fmt: skip
        if n == 1:  # provenance is written once per narrative, even if a replay re-ran the call
            conn.execute(
                _INSERT_CALL,
                {"t": run["tenant_id"], "r": run["run_id"], "p": subject.purpose,
                 "s": subject.subject_ref, "st": res.status, "n": now, **_usage(res)},
            )  # fmt: skip


def load_narratives(conn: Connection, run_id: str) -> list[dict[str, Any]]:
    return [
        dict(r)
        for r in conn.execute(
            text("SELECT * FROM narratives WHERE run_id=:r ORDER BY purpose, subject_ref"),
            {"r": run_id},
        ).mappings()
    ]


def _narrative_result(row: Mapping[str, Any]) -> NarrativeResult:
    body = row["body"] or {}
    out = NarrativeOutput.model_validate(body["output"]) if body.get("output") else None
    return NarrativeResult(
        status=row["status"], output=out, defects=list(row["defects"]), model_id=row["model_id"],
        prompt_version=row["prompt_version"] or "unknown", input_hash=row["input_hash"] or "sha256:" + "0" * 64,
        output_hash=row["output_hash"], attempts=1, input_flags=list(body.get("input_flags", [])),
    )  # fmt: skip


def load_ledgers(conn: Connection, run_id: str) -> list[CoverageLedger]:
    return [
        CoverageLedger.model_validate(b)
        for (b,) in conn.execute(
            text("SELECT body FROM coverage_ledger WHERE run_id=:r ORDER BY segment"),
            {"r": run_id},
        )
    ]


def finding_agents(
    conn: Connection, run_id: str, findings: Mapping[str, Finding]
) -> dict[str, int]:
    """finding_id -> the agent whose adapter produced its evidence (evidence -> task -> adapter)."""
    agent_of_ref: dict[str, int] = {}
    for ref, adapter in conn.execute(
        text("SELECT e.evidence_ref, t.adapter_id FROM evidence_artifacts e "
             "JOIN run_tasks t ON t.task_id = e.task_id WHERE e.run_id=:r"), {"r": run_id},
    ):  # fmt: skip
        if (agent := agent_for_adapter(adapter)) is not None:
            agent_of_ref[ref] = agent
    out: dict[str, int] = {}
    for f in findings.values():
        if (
            a := next((agent_of_ref[r] for r in f.evidence_refs if r in agent_of_ref), None)
        ) is not None:
            out[f.finding_id] = a
    return out


def load_observations(
    conn: Connection, run_id: str, findings: Mapping[str, Finding]
) -> dict[str, tuple[Any, Any]]:
    """finding_id -> (observed, expected). One evidence blob backs many checks, so each finding is
    linked to ITS observation via the deterministic finding id (pack, rule, asset)."""
    pack_ids = {f.policy_version.rsplit(":", 1)[0] for f in findings.values()}
    return {
        finding_id_for(p, rule, a): (obs, exp)
        for a, rule, obs, exp in conn.execute(
            text("SELECT asset_id, rule_id, observed_value, expected_value FROM observations "
                 "WHERE run_id=:r AND outcome='FAIL'"), {"r": run_id},
        )
        for p in pack_ids
    }  # fmt: skip


VERIFICATION_MAX_FINDINGS = 10


def verification_subjects(conn: Connection, run_id: str) -> list[NarrativeSubject]:
    """Agent 4's exposure findings, most severe first, each with its own observed/expected."""
    findings = load_findings(conn, run_id)
    agents = finding_agents(conn, run_id, findings)
    observations = load_observations(conn, run_id, findings)
    exposure = [f for fid, f in findings.items() if agents.get(fid) == 4]
    return [
        verification_subject(f, observations.get(f.finding_id))
        for f in sorted(
            exposure, key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.finding_id)
        )[:VERIFICATION_MAX_FINDINGS]
    ]


# ------------------------------------------------------------------ agent validation pass (ADR-021)
_INSERT_TRIGGER = text(
    "INSERT INTO ai_validation_triggers (tenant_id, run_id, agent_id, target_ref, triggered, rule, "
    "policy_version, policy_sha256, decided_at) VALUES (:t, :r, :a, :ref, :hit, :rule, :v, :h, :n) "
    "ON CONFLICT (run_id, target_ref) DO NOTHING"
)


def record_triggers(
    conn: Connection, run: dict[str, Any], policy: TriggerPolicy,
    decisions: Sequence[TriggerDecision], now: datetime,
) -> None:  # fmt: skip
    """Every decision, triggered or skipped, with the rule and the policy that made it."""
    for d in decisions:
        conn.execute(_INSERT_TRIGGER, {
            "t": run["tenant_id"], "r": run["run_id"], "a": d.agent_id, "ref": d.target_ref[:300],
            "hit": d.triggered, "rule": d.rule[:200], "v": policy.version, "h": policy.sha256,
            "n": now,
        })  # fmt: skip


def validation_packets(
    conn: Connection, run: dict[str, Any], *, batch: int, max_items: int,
    policy: TriggerPolicy | None = None, now: datetime | None = None,
) -> list[ValidationPacket]:  # fmt: skip
    """Packets for Agents 0-6 that the trigger policy selects, in policy priority order. Empty
    unless the run uses AI and has not been validated yet."""
    run_id = run["run_id"]
    if run["ai_mode"] != "enabled":
        return []
    if conn.execute(
        text("SELECT 1 FROM ai_validations WHERE run_id=:r LIMIT 1"), {"r": run_id}
    ).first():
        return []
    ledgers = load_ledgers(conn, run_id)
    findings = load_findings(conn, run_id)
    observations = load_observations(conn, run_id, findings)
    agents = finding_agents(conn, run_id, findings)
    by_agent: dict[int, list[Finding]] = {}
    for f in findings.values():
        if (agent := agents.get(f.finding_id)) in {2, 3, 4}:
            by_agent.setdefault(agent, []).append(f)
    out: list[ValidationPacket] = []
    pol = policy or triggers.load()
    decisions: list[TriggerDecision] = []

    def add(agent_id: int, targets: list[ValidationTarget]) -> None:
        kept, why = triggers.select(pol, agent_id, targets)
        decisions.extend(why)
        out.extend(pk.chunk(agent_id, kept, batch=batch, max_items=max_items))

    add(0, [scope_target(conn, run)])
    add(1, pk.coverage_targets(ledgers))
    for agent_id in sorted(by_agent):
        add(agent_id, pk.finding_targets(by_agent[agent_id], observations))
    add(
        5,
        pk.scenario_targets(
            load_scenarios(conn, run_id).values(), findings, load_risks(conn, run_id)
        ),
    )
    add(6, pk.recommendation_targets(load_recommendations(conn, run_id).values(), findings))
    if now is not None:
        record_triggers(conn, run, pol, decisions, now)
    return [out[i] for i in triggers.order(pol, [p.agent_id for p in out])]


def scope_target(conn: Connection, run: dict[str, Any]) -> ValidationTarget:
    run_id = run["run_id"]
    m = conn.execute(
        text("SELECT manifest_id, body, created_by, approved_by FROM scope_manifests "
             "WHERE manifest_id=:m"), {"m": run["manifest_id"]},
    ).one()  # fmt: skip
    permit = conn.execute(
        text("SELECT allowed_task_types FROM execution_permits WHERE permit_id=:p"),
        {"p": run["permit_id"]},
    ).mappings().first()  # fmt: skip
    tasks = conn.execute(
        text("SELECT adapter_id, task_type, status, expected_assets FROM run_tasks "
             "WHERE run_id=:r ORDER BY adapter_id, task_type"), {"r": run_id},
    ).mappings().all()  # fmt: skip
    expected = {a for t in tasks for a in (t["expected_assets"] or [])}
    return pk.scope_target(
        str(m[0]), m[1], author=m[2], approvers=list(m[3] or []),
        permit=dict(permit) if permit else None, tasks=[dict(t) for t in tasks],
        expected_assets=len(expected),
    )  # fmt: skip


def narrative_packets(
    results: list[tuple[NarrativeSubject, NarrativeResult]], *, batch: int, max_items: int,
    policy: TriggerPolicy | None = None,
) -> tuple[list[ValidationPacket], list[TriggerDecision]]:  # fmt: skip
    """Narratives that passed deterministic grounding in this step: Agent 8 reviews its executive
    summary; Agent 7 reviews every other AI-written text. Returns the trigger decisions too, to be
    recorded with the results."""
    pol = policy or triggers.load()
    items = [
        (f"nar-{s.purpose}-{s.subject_ref}", s, r.output)
        for s, r in results
        if r.status == "VALIDATED" and r.output is not None
    ]
    executive = [i for i in items if i[1].purpose == "executive"]
    others = [i for i in items if i[1].purpose != "executive"]
    k7, d7 = triggers.select(pol, 7, pk.narrative_targets(others))
    k8, d8 = triggers.select(pol, 8, pk.narrative_targets(executive))
    return [
        *pk.chunk(7, k7, batch=batch, max_items=max_items),
        *pk.chunk(8, k8, batch=batch, max_items=max_items),
    ], [*d7, *d8]


# llm_calls shares one status vocabulary across narrative and validation calls.
_CALL_STATUS = {"VALID": "VALIDATED", "VALIDATOR_INVALID": "REJECTED", "UNAVAILABLE": "UNAVAILABLE"}
_INSERT_CALL = text(
    "INSERT INTO llm_calls (tenant_id, run_id, purpose, subject_ref, model_id, prompt_version, "
    "input_hash, output_hash, status, attempts, defects, created_at, input_tokens, output_tokens, "
    "latency_ms, replayed) VALUES (:t, :r, :p, :s, :m, :pv, :ih, :oh, :st, :a, CAST(:d AS jsonb), "
    ":n, :it, :ot, :lat, :rp)"
)


def _usage(res: NarrativeResult | ValidationResult) -> dict[str, Any]:
    return {"m": res.model_id, "pv": res.prompt_version, "ih": res.input_hash,
            "oh": res.output_hash, "a": res.attempts, "d": json.dumps(res.defects),
            "it": res.input_tokens, "ot": res.output_tokens, "lat": res.latency_ms,
            "rp": res.replayed}  # fmt: skip


def usage_totals(conn: Connection, run_id: str) -> dict[str, Any]:
    """What the run's model calls cost, for the report and the model-call ledger."""
    row = conn.execute(
        text("SELECT count(*), coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), "
             "coalesce(sum(latency_ms), 0), count(*) FILTER (WHERE replayed), "
             "count(*) FILTER (WHERE input_tokens IS NULL AND NOT replayed), "
             "count(*) FILTER (WHERE defects ? 'MODEL_BUDGET_EXHAUSTED') "
             "FROM llm_calls WHERE run_id=:r"), {"r": run_id},
    ).one()  # fmt: skip
    return {"calls": row[0], "input_tokens": row[1], "output_tokens": row[2],
            "latency_ms": row[3], "replayed": row[4], "unmetered": row[5],
            "budget_refused": row[6]}  # fmt: skip


def tokens_used(conn: Connection, run_id: str) -> int:
    """Live tokens already spent by a run (replays are free), so a repeated step cannot overspend."""
    return int(conn.execute(
        text("SELECT coalesce(sum(coalesce(input_tokens, 0) + coalesce(output_tokens, 0)), 0) "
             "FROM llm_calls WHERE run_id=:r AND NOT replayed"), {"r": run_id},
    ).scalar_one())  # fmt: skip


def store_validations(
    conn: Connection,
    run: dict[str, Any],
    results: list[tuple[ValidationPacket, ValidationResult]],
    now: datetime,
) -> None:
    for packet, res in results:
        verdicts = {v.target_ref: v for v in (res.output.verdicts if res.output else [])}
        for t in packet.targets:
            v = verdicts.get(t.target_ref) if res.status == "VALID" else None
            verdict = v.verdict if v else ("NO_VERDICT" if res.status == "VALID" else res.status)
            conn.execute(
                text(
                    "INSERT INTO ai_validations (tenant_id, run_id, target_ref, agent_id, packet_id, "
                    "verdict, effect, issues, human_questions, validator_confidence, defects, "
                    "model_id, prompt_version, input_hash, output_hash, created_at) VALUES (:t, :r, "
                    ":ref, :a, :p, :v, :e, CAST(:i AS jsonb), CAST(:q AS jsonb), :c, CAST(:d AS jsonb), "
                    ":m, :pv, :ih, :oh, :n) ON CONFLICT DO NOTHING"
                ),
                {
                    "t": run["tenant_id"], "r": run["run_id"], "ref": t.target_ref,
                    "a": packet.agent_id, "p": packet.packet_id, "v": verdict,
                    "e": effect_for(t.kind, verdict),
                    "i": json.dumps([i.model_dump(mode="json") for i in v.issues] if v else []),
                    "q": json.dumps(v.human_questions if v else []),
                    "c": v.validator_confidence if v else None,
                    "d": json.dumps(res.defects + res.input_flags), "m": res.model_id,
                    "pv": res.prompt_version, "ih": res.input_hash, "oh": res.output_hash, "n": now,
                },
            )  # fmt: skip
        conn.execute(
            _INSERT_CALL,
            {"t": run["tenant_id"], "r": run["run_id"], "p": f"validation:agent-{packet.agent_id}",
             "s": packet.packet_id, "st": _CALL_STATUS[res.status], "n": now, **_usage(res)},
        )  # fmt: skip


def load_ai_verdicts(conn: Connection, run_id: str) -> dict[str, str]:
    """Validator verdicts that still apply: a dissent a human overruled no longer holds anything."""
    return {
        ref: verdict
        for ref, verdict in conn.execute(
            text(
                "SELECT v.target_ref, v.verdict FROM ai_validations v "
                "LEFT JOIN ai_validation_resolutions x ON x.run_id = v.run_id "
                "AND x.target_ref = v.target_ref WHERE v.run_id=:r "
                "AND (x.decision IS NULL OR x.decision <> 'OVERRULE')"
            ),
            {"r": run_id},
        )
    }


def validation_summary(conn: Connection, run_id: str) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    by_agent: dict[str, dict[str, int]] = {}
    models: set[str] = set()
    overruled = upheld = held = 0
    for agent, verdict, effect, model, decision in conn.execute(
        text(
            "SELECT v.agent_id, v.verdict, v.effect, v.model_id, x.decision FROM ai_validations v "
            "LEFT JOIN ai_validation_resolutions x ON x.run_id = v.run_id "
            "AND x.target_ref = v.target_ref WHERE v.run_id=:r"
        ),
        {"r": run_id},
    ):
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        slot = by_agent.setdefault(str(agent), {})
        slot[verdict] = slot.get(verdict, 0) + 1
        overruled += decision == "OVERRULE"
        upheld += decision == "UPHOLD"
        held += effect == "HOLD_FOR_REVIEW" and decision != "OVERRULE"
        if model:
            models.add(model)
    return {
        "total": sum(by_verdict.values()), "by_verdict": by_verdict, "by_agent": by_agent,
        "held_for_review": held,
        "overruled": overruled, "upheld": upheld,
        "unavailable": by_verdict.get("UNAVAILABLE", 0) + by_verdict.get("VALIDATOR_INVALID", 0),
        "models": sorted(models),
    }  # fmt: skip


# ------------------------------------------------------------------ Agent 7 (everything above findings)
def store_assurance_result(
    conn: Connection, tenant: str, run_id: str, res: AssuranceResult, revision: int
) -> None:
    conn.execute(
        text(
            "INSERT INTO assurance_results (tenant_id, run_id, item_ref, verdict, defect_codes, "
            "missing_refs, stale_refs, validation_version, validated_at, revision) VALUES (:t, :r, "
            ":i, :v, CAST(:d AS jsonb), CAST(:m AS jsonb), CAST(:s AS jsonb), :ver, :at, :rev) "
            "ON CONFLICT DO NOTHING"
        ),
        {"t": tenant, "r": run_id, "i": res.item_ref, "v": res.verdict.value,
         "d": json.dumps(res.defect_codes), "m": json.dumps(res.missing_refs),
         "s": json.dumps(res.stale_refs), "ver": res.validation_version, "at": res.validated_at,
         "rev": revision},
    )  # fmt: skip


def current_assurance(conn: Connection, run_id: str, item_ref: str) -> Any:
    """The assurance row of the run's current revision (earlier revisions are history)."""
    return conn.execute(
        text(
            "SELECT a.verdict, a.defect_codes, a.missing_refs, a.stale_refs, a.validation_version, "
            "a.validated_at FROM assurance_results a JOIN assessment_runs r ON r.run_id = a.run_id "
            "AND a.revision = r.assurance_revision WHERE a.run_id=:r AND a.item_ref=:i"
        ),
        {"r": run_id, "i": item_ref},
    ).first()


def assurance_analysis(
    conn: Connection,
    run: dict[str, Any],
    ctx: AssuranceContext,
    *,
    rubric: Rubric,
    catalog: Catalog,
    ai_verdicts: Mapping[str, str] | None = None,
) -> None:
    """``ai_verdicts`` (target_ref -> validator verdict) can only hold ACCEPTed items for review."""
    tenant, run_id, rev = run["tenant_id"], run["run_id"], run["assurance_revision"]
    ai = ai_verdicts or {}
    findings = load_findings(conn, run_id)
    verdicts = {
        fid: AssuranceVerdict(v)
        for fid, v in conn.execute(
            text(
                "SELECT finding_id, assurance_verdict FROM findings WHERE run_id=:r AND assurance_verdict IS NOT NULL"
            ),
            {"r": run_id},
        )
    }
    stored_risks = load_risks(conn, run_id)
    risks: dict[str, RiskAssessment] = {}
    for fid, risk in stored_risks.items():
        res = assess_risk(risk, findings.get(fid), rubric, ctx)
        store_assurance_result(conn, tenant, run_id, res, rev)
        if res.verdict is AssuranceVerdict.ACCEPT:
            risks[fid] = risk  # an irreproducible risk is treated as absent, never trusted

    scenarios = load_scenarios(conn, run_id)
    scenario_verdict: dict[str, AssuranceVerdict] = {}
    for res in assess_scenarios(list(scenarios.values()), findings, verdicts, risks, ctx):
        res = apply_dissent(res, ai.get(res.item_ref))
        store_assurance_result(conn, tenant, run_id, res, rev)
        sid = res.item_ref.removeprefix("scenario:")
        scenario_verdict[sid] = res.verdict
        conn.execute(
            text(
                "UPDATE correlation_scenarios SET assurance_verdict=:v WHERE run_id=:r AND scenario_id=:s"
            ),
            {"v": res.verdict.value, "r": run_id, "s": sid},
        )

    recs = load_recommendations(conn, run_id)
    rec_verdict: dict[str, AssuranceVerdict] = {}
    for rid, rec in recs.items():
        res = apply_dissent(
            assess_recommendation(rec, findings, verdicts, risks, catalog, ctx),
            ai.get(f"recommendation:{rid}"),
        )
        store_assurance_result(conn, tenant, run_id, res, rev)
        rec_verdict[rid] = res.verdict
        conn.execute(
            text(
                "UPDATE recommendations SET assurance_verdict=:v WHERE run_id=:r AND recommendation_id=:i"
            ),
            {"v": res.verdict.value, "r": run_id, "i": rid},
        )

    rows = load_narratives(conn, run_id)
    verification = (
        {s.subject_ref: s for s in verification_subjects(conn, run_id)}
        if any(r["purpose"] == "verification" for r in rows) else {}
    )  # fmt: skip
    for row in rows:
        purpose, ref = row["purpose"], row["subject_ref"]
        if purpose == "scenario" and ref in scenarios:
            subject = scenario_subject(scenarios[ref], findings)
            parent = scenario_verdict.get(ref)
        elif purpose == "recommendation" and ref in recs:
            subject = recommendation_subject(recs[ref], findings)
            parent = rec_verdict.get(ref)
        elif purpose == "verification" and ref in verification:
            subject, parent = verification[ref], verdicts.get(ref)
        elif (
            purpose == "executive"
            and (ex := executive_subject(findings.values(), load_ledgers(conn, run_id))) is not None
        ):
            subject = ex
            output = (row["body"] or {}).get("output") or {}
            cited = {fid for c in output.get("claims", []) for fid in c["finding_ids"]}
            # The summary may speak only for accepted findings, so its parent is the worst of them.
            parent = (
                AssuranceVerdict.ACCEPT
                if cited and all(verdicts.get(f) is AssuranceVerdict.ACCEPT for f in cited)
                else AssuranceVerdict.NEEDS_REVIEW
            )
        else:
            continue
        nres = assess_narrative(_narrative_result(row), subject, parent, ctx)
        if nres is None:
            continue
        nres = apply_dissent(nres, ai.get(f"narrative:{row['narrative_id']}"))
        store_assurance_result(conn, tenant, run_id, nres, rev)
        conn.execute(
            text("UPDATE narratives SET assurance_verdict=:v WHERE run_id=:r AND narrative_id=:n"),
            {"v": nres.verdict.value, "r": run_id, "n": row["narrative_id"]},
        )


# ------------------------------------------------------------------ report assembly
def report_extras(conn: Connection, run: dict[str, Any]) -> dict[str, Any]:
    """Only ACCEPTed items are listed; everything else is counted so the exclusion is disclosed."""
    run_id = run["run_id"]
    risks = {
        fid: r.model_dump(mode="json")
        for fid, r in load_risks(conn, run_id).items()
        if (row := current_assurance(conn, run_id, f"risk:{fid}")) is not None
        and row[0] == "ACCEPT"
    }
    narratives: dict[tuple[str, str], dict[str, Any]] = {}
    ai_total = ai_shown = 0
    models: set[str] = set()
    for n in load_narratives(conn, run_id):
        ai_total += 1
        if n["assurance_verdict"] == "ACCEPT" and (n["body"] or {}).get("output"):
            ai_shown += 1
            narratives[(n["purpose"], n["subject_ref"])] = {
                **n["body"]["output"], "model_id": n["model_id"], "prompt_version": n["prompt_version"],
            }  # fmt: skip
            if n["model_id"]:
                models.add(n["model_id"])
    excluded: dict[str, int] = {}

    def listed(
        rows: list[tuple[str, str | None, dict[str, Any]]], purpose: str, kind: str
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for ident, verdict, body in rows:
            if verdict == "ACCEPT":
                nar = narratives.get((purpose, ident))
                out.append({**body, "narrative": nar} if nar else body)
            else:
                bucket = f"{kind}_{'needs_review' if verdict == 'NEEDS_REVIEW' else 'failed'}"
                excluded[bucket] = excluded.get(bucket, 0) + 1
        return out

    scenarios = listed(
        [(i, v, b) for i, v, b in conn.execute(
            text("SELECT scenario_id, assurance_verdict, body FROM correlation_scenarios "
                 "WHERE run_id=:r ORDER BY scenario_id"), {"r": run_id})],
        "scenario", "scenario",
    )  # fmt: skip
    recommendations = listed(
        [(i, v, b) for i, v, b in conn.execute(
            text("SELECT recommendation_id, assurance_verdict, body FROM recommendations "
                 "WHERE run_id=:r ORDER BY recommendation_id"), {"r": run_id})],
        "recommendation", "recommendation",
    )  # fmt: skip
    executive = narratives.get(("executive", "executive"))
    accepted = accepted_findings(conn, run_id)
    verification = {
        ref: {"questions": n["open_questions"], "model_id": n["model_id"], "ai_generated": True}
        for (purpose, ref), n in narratives.items()
        if purpose == "verification" and ref in accepted
    }
    ai: dict[str, Any] = {"mode": run["ai_mode"], "narratives_total": ai_total,
                          "narratives_accepted": ai_shown, "not_shown": ai_total - ai_shown}  # fmt: skip
    summary = validation_summary(conn, run_id)
    if summary["total"]:
        ai["validation"] = summary
        models |= set(summary["models"])
    usage = usage_totals(conn, run_id)
    if usage["calls"]:
        ai["usage"] = usage
    return {
        "risks": risks, "scenarios": scenarios, "recommendations": recommendations,
        "analysis_excluded": excluded, "model_versions": sorted(models), "ai": ai,
        "executive_summary": executive, "verification_questions": verification,
    }  # fmt: skip


def accepted_findings(conn: Connection, run_id: str) -> set[str]:
    return {
        fid for (fid,) in conn.execute(
            text("SELECT finding_id FROM findings WHERE run_id=:r AND assurance_verdict='ACCEPT'"),
            {"r": run_id},
        )
    }  # fmt: skip
