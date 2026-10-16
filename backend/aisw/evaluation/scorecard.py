"""Score one run against the evaluation targets (implementation plan §7.2, ADR-039).

Every number is computed from what the run recorded; nothing is typed in. A metric that cannot be
measured for this run says NOT_MEASURED and why, rather than defaulting to a pass. Recall and
precision exist only when an answer key matches the run's fixture set and policy version. The
validator catch-rate comes from the offline labelled evaluation (ADR-025), never from this run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Any, Literal

from sqlalchemy import Connection, text

from aisw.agents.safety import COMPLIANCE
from aisw.contracts.base import canonical_hash
from aisw.evaluation.answer_key import AnswerKey, for_fixture
from aisw.policy.results import finding_id_for
from aisw.reporting.report import DISCLAIMER

Status = Literal["MET", "NOT_MET", "MEASURED", "NOT_MEASURED"]
RECONCILIATION_TARGET = 0.95
CATCH_RATE_TARGET = 0.90
FALSE_DISSENT_TARGET = 0.10
EXECUTED = ("SUCCEEDED", "PARTIAL")
TAG = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class RunFacts:
    run_id: str
    policy_version: str
    fixture_set: str | None
    expected: frozenset[str]
    statuses: dict[str, str]
    flagged_absent: frozenset[str]
    flagged_unexpected: frozenset[str]
    findings: dict[str, list[str]]  # finding_id -> evidence refs
    evidence: frozenset[str]
    observations: dict[tuple[str, str], tuple[str, str | None]]  # (rule, asset) -> outcome, ref
    exceptions: frozenset[tuple[str, str]]
    report_text: str | None
    control_gaps: dict[str, Any] | None
    violations: list[str]
    blocked_tasks: int
    model_calls: list[tuple[int | None, int | None, int, str]] = field(default_factory=list)
    digest: str = ""


def _metric(
    metric: str, label: str, target: str, status: Status, value: float | int | None,
    display: str, detail: dict[str, Any] | None = None,
) -> dict[str, Any]:  # fmt: skip
    return {"metric": metric, "label": label, "target": target, "status": status,
            "value": value, "display": display, "detail": detail or {}}  # fmt: skip


def _pct(n: int, d: int) -> str:
    return f"{n} of {d} ({round(100 * n / d, 1)}%)" if d else "0 of 0"


def _reconciliation(f: RunFacts, key: AnswerKey | None) -> dict[str, Any]:
    found = set(f.statuses)
    union = f.expected | found
    matched = f.expected & found
    flagged = (f.flagged_absent & (f.expected - found)) | (
        f.flagged_unexpected & (found - f.expected)
    )
    silent = sorted(union - matched - flagged)
    detail: dict[str, Any] = {
        "matched": len(matched), "absent_flagged": len(f.flagged_absent & (f.expected - found)),
        "unexpected_flagged": len(f.flagged_unexpected & (found - f.expected)),
        "unaccounted": silent[:50],
    }  # fmt: skip
    if not f.expected:
        detail["reason"] = "NO_EXPECTED_ASSET_LIST"
    if key is not None:
        mine = {a: "MATCHED" for a in matched}
        mine |= {a: "ABSENT" for a in f.expected - found}
        mine |= {a: "UNEXPECTED" for a in found - f.expected}
        wrong = sorted(a for a, want in key.reconciliation.items() if mine.get(a) != want)
        detail["answer_key_agreement"] = {"agree": len(key.reconciliation) - len(wrong),
                                          "of": len(key.reconciliation), "disagree": wrong[:50]}  # fmt: skip
    if not union:
        return _metric("asset_reconciliation", "Asset reconciliation",
                       "≥ 95% reconciled or explicitly unresolved", "NOT_MEASURED", None,
                       "No assets in scope or discovered", detail)  # fmt: skip
    rate = (len(matched) + len(flagged)) / len(union)
    return _metric("asset_reconciliation", "Asset reconciliation",
                   "≥ 95% reconciled or explicitly unresolved",
                   "MET" if rate >= RECONCILIATION_TARGET else "NOT_MET", round(rate, 4),
                   _pct(len(matched) + len(flagged), len(union)), detail)  # fmt: skip


def _status_coverage(f: RunFacts, key: AnswerKey | None) -> dict[str, Any]:
    union = f.expected | set(f.statuses)
    has = {a for a in union if a in f.statuses or a in f.flagged_absent}
    by: dict[str, int] = {}
    for a in union:
        s = f.statuses.get(a, "ABSENT" if a in f.flagged_absent else "NONE")
        by[s] = by.get(s, 0) + 1
    detail: dict[str, Any] = {"by_status": dict(sorted(by.items())),
                              "without_status": sorted(union - has)[:50]}  # fmt: skip
    if key is not None:
        wrong = sorted(a for a, s in key.asset_status.items() if f.statuses.get(a) != s)
        detail["answer_key_agreement"] = {"agree": len(key.asset_status) - len(wrong),
                                          "of": len(key.asset_status), "disagree": wrong[:50]}  # fmt: skip
    if not union:
        return _metric("status_coverage", "Assessment status coverage",
                       "100% of in-scope assets have a status", "NOT_MEASURED", None,
                       "No assets in scope", detail)  # fmt: skip
    return _metric("status_coverage", "Assessment status coverage",
                   "100% of in-scope assets have a status",
                   "MET" if len(has) == len(union) else "NOT_MET", round(len(has) / len(union), 4),
                   _pct(len(has), len(union)), detail)  # fmt: skip


def _missed_reason(f: RunFacts, rule: str, asset: str) -> str:
    status = f.statuses.get(asset)
    if status is None:
        return "ASSET_ABSENT" if asset in f.expected else "ASSET_NOT_IN_SCOPE"
    if status != "SCANNED":
        return f"ASSET_{status}"
    obs = f.observations.get((rule, asset))
    if obs is None:
        return "NOT_ASSESSED: the collector returned no value for this check"
    return {
        "UNKNOWN": "UNKNOWN: the collector returned an empty value, so the check was undecided",
        "PASS": "PASS: the collected value passed (the evidence disagrees with the ground truth)",
    }.get(obs[0], f"{obs[0]}: the check could not be evaluated")


def _detection(f: RunFacts, key: AnswerKey | None) -> list[dict[str, Any]]:
    label_r, label_p = "Known-issue detection: recall", "Known-issue detection: precision"
    target = "Measured when an answer key is provided"
    if key is None:
        why = "No answer key matches this run's fixture set and policy version"
        return [_metric("detection_recall", label_r, target, "NOT_MEASURED", None, why),
                _metric("detection_precision", label_p, target, "NOT_MEASURED", None, why)]  # fmt: skip
    ids = {finding_id_for(key.pack_id, c.rule_id, c.asset_id): (c.rule_id, c.asset_id)
           for c in key.known_issues}  # fmt: skip
    clean = {finding_id_for(key.pack_id, c.rule_id, c.asset_id): (c.rule_id, c.asset_id)
             for c in key.known_clean}  # fmt: skip
    hit = [c for c in key.known_issues if finding_id_for(key.pack_id, c.rule_id, c.asset_id)
           in f.findings or (c.rule_id, c.asset_id) in f.exceptions]  # fmt: skip
    missed = [{"rule_id": c.rule_id, "asset_id": c.asset_id,
               "reason": _missed_reason(f, c.rule_id, c.asset_id)}
              for c in key.known_issues if c not in hit]  # fmt: skip
    true_pos = [fid for fid in f.findings if fid in ids]
    false_pos = [{"finding_id": fid, "rule_id": clean[fid][0], "asset_id": clean[fid][1]}
                 for fid in sorted(f.findings) if fid in clean]  # fmt: skip
    unlabelled = sorted(fid for fid in f.findings if fid not in ids and fid not in clean)
    n_issues, n_found = len(key.known_issues), len(f.findings)
    recall = _metric(
        "detection_recall", label_r, target, "MEASURED",
        round(len(hit) / n_issues, 4) if n_issues else None, _pct(len(hit), n_issues),
        {"detected": len(hit), "known_issues": n_issues, "missed": missed},
    )  # fmt: skip
    precision = _metric(
        "detection_precision", label_p, target, "MEASURED" if n_found else "NOT_MEASURED",
        round(len(true_pos) / n_found, 4) if n_found else None,
        _pct(len(true_pos), n_found) if n_found else "No findings raised",
        {"true_positive": len(true_pos), "findings": n_found, "false_positive": false_pos,
         "unlabelled": unlabelled[:50]},
    )  # fmt: skip
    return [recall, precision]


def _traceability(f: RunFacts) -> dict[str, Any]:
    refs = {ref for _, ref in f.observations.values() if ref}
    broken = sorted(fid for fid, ev in f.findings.items()
                    if not ev or any(r not in f.evidence or r not in refs for r in ev))  # fmt: skip
    n = len(f.findings)
    return _metric(
        "finding_traceability", "Finding traceability", "100%",
        "MET" if not broken else "NOT_MET", round((n - len(broken)) / n, 4) if n else 1.0,
        _pct(n - len(broken), n) if n else "No findings to trace",
        {"untraceable": broken[:50],
         "rule": "every evidence ref is stored for this run and backs a recorded observation"},
    )  # fmt: skip


def _compliance_claims(f: RunFacts) -> dict[str, Any]:
    if f.report_text is None:
        return _metric("unsupported_compliance_claims", "Unsupported compliance claims", "0",
                       "NOT_MEASURED", None, "No report generated for this run")  # fmt: skip
    body = " ".join(f.report_text.split()).replace(" ".join(DISCLAIMER.split()), " ")
    phrases = sorted({m.group(0) for m in COMPLIANCE.finditer(body)})
    overclaimed: list[str] = []
    for fw in (f.control_gaps or {}).get("frameworks", []):
        for row in fw["rows"]:
            ok = all(p["outcome"] in {"PASS", "NOT_APPLICABLE"} for p in row["pack_controls"])
            if row["state"] == "NO_GAP_OBSERVED" and not (ok and row["pack_controls"]):
                overclaimed.append(f"{fw['framework']} {row['control_id']}")
    count = len(phrases) + len(overclaimed)
    return _metric(
        "unsupported_compliance_claims", "Unsupported compliance claims", "0",
        "MET" if count == 0 else "NOT_MET", count, str(count),
        {"phrases": phrases, "gap_rows_without_support": overclaimed[:50],
         "checked": "report text (except the fixed disclaimer) and every control-gap row"},
    )  # fmt: skip


def _scope(f: RunFacts) -> dict[str, Any]:
    n = len(f.violations)
    return _metric(
        "scope_enforcement", "Scope enforcement / unauthorised change attempts", "0 successful",
        "MET" if n == 0 else "NOT_MET", n, f"{n} successful, {f.blocked_tasks} blocked",
        {"violations": f.violations, "blocked_tasks": f.blocked_tasks},
    )  # fmt: skip


def _validator(labelled: dict[str, Any] | None) -> list[dict[str, Any]]:
    lc, lf = "Astra validator catch-rate (seeded bad outcomes)", "Astra false-dissent rate"
    if labelled is None:
        why = "Measured offline on the synthetic labelled set by tools/eval_labelled.py"
        return [_metric("validator_catch_rate", lc, "Proposed ≥ 90%", "NOT_MEASURED", None, why),
                _metric("validator_false_dissent", lf, "Proposed ≤ 10%", "NOT_MEASURED", None,
                        why)]  # fmt: skip
    m = labelled["metrics"]
    src = {"set_version": labelled["set_version"], "model_id": labelled.get("model_id"),
           "generated_at": labelled["generated_at"], "decision": labelled["decision"]}  # fmt: skip
    catch, dissent = m.get("recall"), m.get("false_dissent_rate")
    return [
        _metric("validator_catch_rate", lc, "Proposed ≥ 90%",
                "NOT_MEASURED" if catch is None else "MET" if catch >= CATCH_RATE_TARGET
                else "NOT_MET", catch,
                _pct(int(m["detected"]), int(m["defect_cases"])), src),
        _metric("validator_false_dissent", lf, "Proposed ≤ 10%",
                "NOT_MEASURED" if dissent is None else "MET" if dissent <= FALSE_DISSENT_TARGET
                else "NOT_MET", dissent,
                f"{dissent} over {m['clean_cases']} clean cases", src),
    ]  # fmt: skip


def _reproducibility(f: RunFacts, previous: tuple[str, str] | None) -> dict[str, Any]:
    label, target = "Reproducibility of the deterministic layer", "100%"
    if previous is None:
        return _metric("reproducibility", label, target, "NOT_MEASURED", None,
                       "No earlier run with identical inputs to compare against",
                       {"digest": f.digest})  # fmt: skip
    same = previous[1] == f.digest
    return _metric("reproducibility", label, target, "MET" if same else "NOT_MET",
                   1.0 if same else 0.0, "Identical" if same else "Differs",
                   {"digest": f.digest, "compared_with": previous[0],
                    "compared_digest": previous[1]})  # fmt: skip


def _model_cost(f: RunFacts) -> dict[str, Any]:
    calls = f.model_calls
    label, target = "Astra cost/latency per run", "Measured and reported"
    if not calls:
        return _metric("model_cost_latency", label, target, "MEASURED", 0,
                       "No model calls in this run", {"calls": 0})  # fmt: skip
    tin = sum(c[0] or 0 for c in calls)
    tout = sum(c[1] or 0 for c in calls)
    lat = [c[2] for c in calls]
    return _metric(
        "model_cost_latency", label, target, "MEASURED", tin + tout,
        f"{len(calls)} calls, {tin + tout} tokens, {sum(lat)} ms total",
        {"calls": len(calls), "input_tokens": tin, "output_tokens": tout,
         "unmetered_calls": sum(c[0] is None for c in calls), "latency_ms_total": sum(lat),
         "latency_ms_max": max(lat), "not_validated_calls": sum(c[3] != "VALIDATED" for c in calls)},
    )  # fmt: skip


def score(
    f: RunFacts, key: AnswerKey | None, *, labelled: dict[str, Any] | None = None,
    previous: tuple[str, str] | None = None,
) -> dict[str, Any]:  # fmt: skip
    metrics = [
        _reconciliation(f, key), _status_coverage(f, key), *_detection(f, key), _traceability(f),
        _compliance_claims(f), _scope(f), *_validator(labelled), _reproducibility(f, previous),
        _model_cost(f),
    ]  # fmt: skip
    summary = {s: sum(m["status"] == s for m in metrics)
               for s in ("MET", "NOT_MET", "MEASURED", "NOT_MEASURED")}  # fmt: skip
    return {
        "run_id": f.run_id, "policy_version": f.policy_version, "fixture_set": f.fixture_set,
        "answer_key": None if key is None else {"key_id": key.key_id, "note": key.note},
        "metrics": metrics, "summary": summary,
    }  # fmt: skip


# ---- collection from the database ---------------------------------------------------------------
def _reasons(ledgers: list[dict[str, Any]], prefix: str) -> frozenset[str]:
    return frozenset(r.split(":")[1] for L in ledgers for r in L.get("reasons", [])
                     if r.startswith(prefix + ":"))  # fmt: skip


def _scope_violations(tasks: list[Any], body: dict[str, Any]) -> list[str]:
    targets = {(t["kind"], t["selector"]) for t in body.get("targets", [])}
    excluded = {(t["kind"], t["selector"]) for t in body.get("exclusions", [])}
    out = []
    for t in tasks:
        if t.status not in EXECUTED:
            continue
        where = f"task {t.task_id} ({t.adapter_id} on {t.target_kind} {t.target_selector})"
        prof = body.get("profiles", {}).get(t.adapter_id)
        if t.adapter_id not in body.get("allowed_adapters", []):
            out.append(f"{where}: adapter not allowed by the manifest")
        if prof is None or prof["profile_id"] != t.profile:
            out.append(f"{where}: profile not approved in the manifest")
        elif prof["profile_class"] != "READ_ONLY":
            out.append(f"{where}: profile is not read-only")
        if (t.target_kind, t.target_selector) not in targets:
            out.append(f"{where}: target not in the manifest")
        if (t.target_kind, t.target_selector) in excluded:
            out.append(f"{where}: target is excluded")
    return out


def signature(tasks: list[Any], policy_version: str) -> str:
    """Inputs that must match for two runs to be expected to give identical results."""
    return canonical_hash({"policy": policy_version, "tasks": sorted(
        json.dumps([t.adapter_id, t.profile, t.target_kind, t.target_selector, t.params,
                    sorted(t.expected_assets)], sort_keys=True) for t in tasks)})  # fmt: skip


def collect(conn: Connection, run_id: str) -> tuple[RunFacts, str] | None:
    """Facts for one run plus its input signature, or None when the run has no report yet."""
    run = conn.execute(
        text("SELECT r.run_id, r.policy_version, m.body AS manifest FROM assessment_runs r "
             "JOIN scope_manifests m ON m.manifest_id=r.manifest_id WHERE r.run_id=:r"),
        {"r": run_id},
    ).first()  # fmt: skip
    report = conn.execute(
        text("SELECT body, html FROM reports WHERE run_id=:r ORDER BY generated_at DESC, "
             "report_id DESC LIMIT 1"), {"r": run_id},
    ).first()  # fmt: skip
    if run is None or report is None:
        return None
    q = {"r": run_id}
    tasks = conn.execute(
        text("SELECT task_id, adapter_id, profile, target_kind, target_selector, params, "
             "expected_assets, status FROM run_tasks WHERE run_id=:r ORDER BY created_at"), q,
    ).all()  # fmt: skip
    statuses: dict[str, str] = {}
    for a, s in conn.execute(
        text("SELECT asset_id, status FROM run_asset_status WHERE run_id=:r ORDER BY asset_id"), q
    ):
        statuses.setdefault(a, s)
    ledgers = [r[0] for r in conn.execute(
        text("SELECT body FROM coverage_ledger WHERE run_id=:r ORDER BY segment"), q)]  # fmt: skip
    findings = {r[0]: list(r[1].get("evidence_refs", [])) for r in conn.execute(
        text("SELECT finding_id, body FROM findings WHERE run_id=:r"), q)}  # fmt: skip
    evidence = frozenset(r[0] for r in conn.execute(
        text("SELECT evidence_ref FROM evidence_artifacts WHERE run_id=:r"), q))  # fmt: skip
    obs_rows = conn.execute(
        text("SELECT rule_id, asset_id, outcome, evidence_ref, observed_value FROM observations "
             "WHERE run_id=:r ORDER BY rule_id, asset_id"), q,
    ).all()  # fmt: skip
    exceptions = frozenset((r[0], r[1]) for r in conn.execute(
        text("SELECT rule_id, asset_id FROM exception_applications WHERE run_id=:r"), q))  # fmt: skip
    controls = sorted((r[0], r[1], r[2]) for r in conn.execute(
        text("SELECT framework, control_id, outcome FROM control_assessments WHERE run_id=:r"), q))  # fmt: skip
    calls = [(r[0], r[1], int(r[2]), str(r[3])) for r in conn.execute(
        text("SELECT input_tokens, output_tokens, latency_ms, status FROM llm_calls "
             "WHERE run_id=:r"), q)]  # fmt: skip
    fixture = next((t.params.get("fixture_set") for t in tasks if t.adapter_id == "fixture"), None)
    deterministic = {
        "assets": sorted(statuses.items()),
        "observations": [[r[0], r[1], r[2], r[4]] for r in obs_rows],
        "controls": controls,
        "findings": sorted(findings),
        "coverage": [{k: L[k] for k in ("segment", "expected_count", "discovered_count",
                      "reconciled_count", "excluded_count", "unsupported_count", "unknown_count",
                      "assessed_by_outcome", "source_ok")} for L in ledgers],
    }  # fmt: skip
    body = report[0]
    facts = RunFacts(
        run_id=run_id, policy_version=run.policy_version,
        fixture_set=str(fixture) if fixture else None,
        expected=frozenset(a for t in tasks for a in t.expected_assets), statuses=statuses,
        flagged_absent=_reasons(ledgers, "EXPECTED_ASSET_ABSENT"),
        flagged_unexpected=_reasons(ledgers, "UNEXPECTED_ASSET"),
        findings=findings, evidence=evidence,
        observations={(r[0], r[1]): (r[2], r[3]) for r in obs_rows}, exceptions=exceptions,
        report_text=unescape(TAG.sub(" ", report[1])) if report[1] else None,
        control_gaps=body.get("control_gaps"),
        violations=_scope_violations(list(tasks), run.manifest),
        blocked_tasks=sum(t.status == "REJECTED" for t in tasks), model_calls=calls,
        digest=canonical_hash(deterministic),
    )  # fmt: skip
    return facts, signature(list(tasks), run.policy_version)


def previous_digest(conn: Connection, facts: RunFacts, sig: str) -> tuple[str, str] | None:
    """Most recent earlier reported run with identical inputs, and its deterministic digest."""
    for other, _created in conn.execute(
        text("SELECT DISTINCT r.run_id, r.created_at FROM assessment_runs r "
             "JOIN assessment_runs me ON me.run_id=:r JOIN reports p ON p.run_id=r.run_id "
             "WHERE r.policy_version=me.policy_version AND r.run_id<>me.run_id "
             "AND r.created_at <= me.created_at AND NOT EXISTS ("
             "  SELECT t.adapter_id, t.params, t.expected_assets FROM run_tasks t "
             "  WHERE t.run_id=me.run_id EXCEPT "
             "  SELECT u.adapter_id, u.params, u.expected_assets FROM run_tasks u "
             "  WHERE u.run_id=r.run_id) "
             "ORDER BY r.created_at DESC LIMIT 25"),
        {"r": facts.run_id},
    ).all():  # fmt: skip
        got = collect(conn, other)
        if got is not None and got[1] == sig:
            return other, got[0].digest
    return None


def run_scorecard(
    conn: Connection, run_id: str, *, labelled: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    got = collect(conn, run_id)
    if got is None:
        return None
    facts, sig = got
    key = for_fixture(facts.fixture_set, facts.policy_version)
    return score(facts, key, labelled=labelled, previous=previous_digest(conn, facts, sig))
