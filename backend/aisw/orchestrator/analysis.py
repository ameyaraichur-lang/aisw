"""Run-level analysis phases (Agents 5, 6 and the assurance of their output).

Pure functions over a tenant-scoped connection, so the worker keeps ownership of transactions,
locking and state transitions. The model is NEVER called from here: pending narrative subjects are
returned to the worker, which calls the gateway outside the run-row lock.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
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
from aisw.contracts.analysis import CorrelationScenario, RiskAssessment, RiskFactors
from aisw.contracts.assurance import AssuranceResult
from aisw.contracts.domain import Finding, Recommendation
from aisw.contracts.enums import AssuranceVerdict
from aisw.llm.gateway import NarrativeResult
from aisw.llm.schema import NarrativeOutput, NarrativeSubject
from aisw.llm.subject import recommendation_subject, scenario_subject
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
                text(
                    "INSERT INTO llm_calls (tenant_id, run_id, purpose, subject_ref, model_id, "
                    "prompt_version, input_hash, output_hash, status, attempts, defects, created_at) "
                    "VALUES (:t, :r, :p, :s, :m, :pv, :ih, :oh, :st, :a, CAST(:d AS jsonb), :n)"
                ),
                {"t": run["tenant_id"], "r": run["run_id"], "p": subject.purpose,
                 "s": subject.subject_ref, "m": res.model_id, "pv": res.prompt_version,
                 "ih": res.input_hash, "oh": res.output_hash, "st": res.status, "a": res.attempts,
                 "d": json.dumps(res.defects), "n": now},
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


# ------------------------------------------------------------------ Agent 7 (everything above findings)
def _store_result(conn: Connection, tenant: str, run_id: str, res: AssuranceResult) -> None:
    conn.execute(
        text(
            "INSERT INTO assurance_results (tenant_id, run_id, item_ref, verdict, defect_codes, "
            "missing_refs, stale_refs, validation_version, validated_at) VALUES (:t, :r, :i, :v, "
            "CAST(:d AS jsonb), CAST(:m AS jsonb), CAST(:s AS jsonb), :ver, :at) ON CONFLICT DO NOTHING"
        ),
        {"t": tenant, "r": run_id, "i": res.item_ref, "v": res.verdict.value,
         "d": json.dumps(res.defect_codes), "m": json.dumps(res.missing_refs),
         "s": json.dumps(res.stale_refs), "ver": res.validation_version, "at": res.validated_at},
    )  # fmt: skip


def assurance_analysis(
    conn: Connection,
    run: dict[str, Any],
    ctx: AssuranceContext,
    *,
    rubric: Rubric,
    catalog: Catalog,
) -> None:
    tenant, run_id = run["tenant_id"], run["run_id"]
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
        _store_result(conn, tenant, run_id, res)
        if res.verdict is AssuranceVerdict.ACCEPT:
            risks[fid] = risk  # an irreproducible risk is treated as absent, never trusted

    scenarios = load_scenarios(conn, run_id)
    scenario_verdict: dict[str, AssuranceVerdict] = {}
    for res in assess_scenarios(list(scenarios.values()), findings, verdicts, risks, ctx):
        _store_result(conn, tenant, run_id, res)
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
        res = assess_recommendation(rec, findings, verdicts, risks, catalog, ctx)
        _store_result(conn, tenant, run_id, res)
        rec_verdict[rid] = res.verdict
        conn.execute(
            text(
                "UPDATE recommendations SET assurance_verdict=:v WHERE run_id=:r AND recommendation_id=:i"
            ),
            {"v": res.verdict.value, "r": run_id, "i": rid},
        )

    for row in load_narratives(conn, run_id):
        purpose, ref = row["purpose"], row["subject_ref"]
        if purpose == "scenario" and ref in scenarios:
            subject = scenario_subject(scenarios[ref], findings)
            parent = scenario_verdict.get(ref)
        elif purpose == "recommendation" and ref in recs:
            subject = recommendation_subject(recs[ref], findings)
            parent = rec_verdict.get(ref)
        else:
            continue
        nres = assess_narrative(_narrative_result(row), subject, parent, ctx)
        if nres is None:
            continue
        _store_result(conn, tenant, run_id, nres)
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
        if (
            conn.execute(
                text("SELECT verdict FROM assurance_results WHERE run_id=:r AND item_ref=:i"),
                {"r": run_id, "i": f"risk:{fid}"},
            ).scalar()
            == "ACCEPT"
        )
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
    return {
        "risks": risks, "scenarios": scenarios, "recommendations": recommendations,
        "analysis_excluded": excluded, "model_versions": sorted(models),
        "ai": {"mode": run["ai_mode"], "narratives_total": ai_total,
               "narratives_accepted": ai_shown, "not_shown": ai_total - ai_shown},
    }  # fmt: skip
