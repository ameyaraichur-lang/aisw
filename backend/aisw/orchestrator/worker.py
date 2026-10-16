"""Durable, PostgreSQL-backed orchestration worker (ADR-002).

* Work is claimed with ``FOR UPDATE SKIP LOCKED`` plus a lease. A crashed worker's task becomes
  claimable again when the lease expires; attempts are bounded.
* State is persisted before dispatch (claim) and after completion (ingest + status + events in ONE
  transaction), so every phase is replay-safe: evidence is content-addressed, assets/observations
  are keyed deterministically and inserted with ON CONFLICT DO NOTHING.
* All data access happens inside a tenant context. The worker role may DISCOVER open work across
  tenants (RLS policy ``worker_discover``) but cannot read anything else without a tenant.
* The only way to reach an adapter is ``ToolGateway.dispatch``.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, text

from aisw.agents.assurance import ArtifactMeta, AssuranceContext, assess_finding
from aisw.agents.discovery import KnownAsset, resolve_identity
from aisw.contracts.base import canonical_hash
from aisw.contracts.domain import ControlMapping, Finding
from aisw.contracts.enums import PolicyOutcome
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.redaction import redact_obj
from aisw.evidence.ingest import IngestRejected, evidence_ref, prepare, store_evidence
from aisw.evidence.store import EvidenceStore
from aisw.gateway.gateway import GatewayDenied, ToolGateway, ToolRequest
from aisw.gateway.registry import AdapterOutput, AdapterRegistry
from aisw.orchestrator.events import append_event
from aisw.policy.engine import PackRegistry, PolicyEvaluator, PolicyPack
from aisw.policy.results import RuleResult, dedupe_key, finding_id, rollup
from aisw.reporting.coverage import build_ledger
from aisw.reporting.report import ReportInputs, build_report

_SELECT_RUN = "SELECT * FROM assessment_runs WHERE run_id=:r"
_SELECT_RUN_LOCKED = _SELECT_RUN + " FOR UPDATE"
TRANSIENT_DENIALS = {"AUDIT_UNAVAILABLE"}
# Task warnings that describe a coverage gap and are surfaced verbatim in the coverage ledger.
GAP_PREFIXES = frozenset(
    {"AMBIGUOUS_IDENTITY", "OUT_OF_SCOPE_RECORDS_DROPPED", "PERMISSION_DENIED", "STALE_RECORD",
     "OWNER_UNKNOWN", "DUPLICATE_CANDIDATE", "CONFLICTING_RECORDS", "UNSUPPORTED_SERVICE",
     "AGENT_DISCONNECTED", "FEED_STALE", "SCAN_INCOMPLETE", "RULES_NOT_CHECKED"}
)  # fmt: skip
ADVANCEABLE = (
    "AUTHORIZED",
    "ASSESSMENT_DISPATCH",
    "NORMALIZATION",
    "POLICY_EVALUATION",
    "ASSURANCE",
)


@dataclass
class Worker:
    engine: Engine
    gateway: ToolGateway
    registry: AdapterRegistry
    packs: PackRegistry
    evaluator: PolicyEvaluator
    evidence: EvidenceStore
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    worker_id: str = "worker-1"
    lease: timedelta = timedelta(minutes=5)
    freshness: timedelta = timedelta(hours=24)
    backoff_base_seconds: float = 2.0

    # ------------------------------------------------------------------ main loop
    def step(self) -> bool:
        task = self.claim()
        if task is not None:
            self.process(task)
            return True
        return self.advance_one()

    def run_until_idle(self, max_steps: int = 500) -> int:
        n = 0
        while n < max_steps and self.step():
            n += 1
        return n

    # ------------------------------------------------------------------ claiming
    def claim(self) -> dict[str, Any] | None:
        now = self.clock()
        with self.engine.begin() as conn:
            while True:
                row = (
                    conn.execute(
                        text(
                            "SELECT * FROM run_tasks WHERE (status='QUEUED' AND available_at <= :n) "
                            "OR (status='RUNNING' AND locked_until < :n) "
                            "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1"
                        ),
                        {"n": now},
                    )
                    .mappings()
                    .first()
                )
                if row is None:
                    return None
                self._set_tenant(conn, row["tenant_id"])
                if row["status"] == "RUNNING" and row["attempts"] >= row["max_attempts"]:
                    self._finish(conn, dict(row), "FAILED", errors=["LEASE_EXPIRED_MAX_ATTEMPTS"])
                    continue
                claimed = (
                    conn.execute(
                        text(
                            "UPDATE run_tasks SET status='RUNNING', locked_by=:w, "
                            "locked_until=:u, attempts=attempts+1, "
                            "started_at=COALESCE(started_at, :n) WHERE task_id=:t RETURNING *"
                        ),
                        {"w": self.worker_id, "u": now + self.lease, "n": now, "t": row["task_id"]},
                    )
                    .mappings()
                    .one()
                )
                append_event(
                    conn, tenant_id=row["tenant_id"], run_id=row["run_id"], now=now,
                    event_type="task.started",
                    payload={"task_id": str(row["task_id"]), "agent_id": row["adapter_id"],
                             "domain": row["target_kind"], "attempt": claimed["attempts"],
                             "started_at": now.isoformat()},
                )  # fmt: skip
                return dict(claimed)

    @staticmethod
    def _set_tenant(conn: Connection, tenant_id: str) -> None:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant_id})

    # ------------------------------------------------------------------ fencing
    def _owns(self, conn: Connection, task: dict[str, Any]) -> bool:
        """Fencing token = (worker, attempt). A worker whose lease expired and whose task was
        re-claimed must not write anything: its transaction is abandoned instead."""
        return (
            conn.execute(
                text(
                    "SELECT 1 FROM run_tasks WHERE task_id=:t AND status='RUNNING' "
                    "AND locked_by=:w AND attempts=:a FOR UPDATE"
                ),
                {"t": task["task_id"], "w": self.worker_id, "a": task["attempts"]},
            ).first()
            is not None
        )

    def _finish_if_owner(
        self, conn: Connection, task: dict[str, Any], status: str, **kw: Any
    ) -> None:
        if self._owns(conn, task):
            self._finish(conn, task, status, **kw)

    # ------------------------------------------------------------------ task processing
    def process(self, task: dict[str, Any]) -> None:
        tenant = task["tenant_id"]
        with tenant_connection(self.engine, tenant) as conn:
            run = self._run(conn, task["run_id"])
            if run["cancel_requested"]:
                self._finish_if_owner(conn, task, "CANCELLED", errors=["CANCELLED_BEFORE_START"])
                return
        req = ToolRequest(
            tenant_id=tenant, project_id=str(run["project_id"]), run_id=task["run_id"],
            task_id=str(task["task_id"]), task_type=task["task_type"], adapter_id=task["adapter_id"],
            profile=task["profile"], target_kind=task["target_kind"],
            target_selector=task["target_selector"], params=task["params"],
            permit_id=str(run["permit_id"]), manifest_hash=run["manifest_hash"],
        )  # fmt: skip
        try:
            result = self.gateway.dispatch(req)
        except GatewayDenied as exc:
            if set(exc.reason_codes) <= TRANSIENT_DENIALS:
                self._retry_or_fail(task, exc.reason_codes)
            else:
                with tenant_connection(self.engine, tenant) as conn:
                    self._finish_if_owner(conn, task, "REJECTED", errors=exc.reason_codes)
            return
        except Exception as exc:  # adapter crash/timeout: bounded retry with backoff + jitter
            self._retry_or_fail(task, [f"ADAPTER_ERROR:{type(exc).__name__}"])
            return
        output = result.adapter_result
        if not isinstance(output, AdapterOutput):
            with tenant_connection(self.engine, tenant) as conn:
                self._finish_if_owner(conn, task, "FAILED", errors=["BAD_ADAPTER_OUTPUT"])
            return
        self._ingest(task, run, output, result.warnings)

    def _retry_or_fail(self, task: dict[str, Any], codes: list[str]) -> None:
        now = self.clock()
        with tenant_connection(self.engine, task["tenant_id"]) as conn:
            if not self._owns(conn, task):
                return
            if task["attempts"] >= task["max_attempts"]:
                self._finish(conn, task, "FAILED", errors=[*codes, "RETRIES_EXHAUSTED"])
                return
            delay = self.backoff_base_seconds * (2 ** (task["attempts"] - 1))
            delay += random.uniform(0, delay * 0.1)  # noqa: S311 - jitter, not security
            conn.execute(
                text(
                    "UPDATE run_tasks SET status='QUEUED', locked_by=NULL, locked_until=NULL, "
                    "available_at=:a, errors=CAST(:e AS jsonb) WHERE task_id=:t"
                ),
                {"a": now + timedelta(seconds=delay), "e": json.dumps(codes), "t": task["task_id"]},
            )
            append_event(
                conn, tenant_id=task["tenant_id"], run_id=task["run_id"], now=now,
                event_type="task.progress",
                payload={"task_id": str(task["task_id"]), "note": "retry scheduled",
                         "attempt": task["attempts"], "codes": codes},
            )  # fmt: skip

    def _ingest(
        self, task: dict[str, Any], run: dict[str, Any], output: AdapterOutput, gw_warnings: Any
    ) -> None:
        tenant, project, run_id = task["tenant_id"], str(run["project_id"]), task["run_id"]
        adapter = self.registry.get(task["adapter_id"])
        normalize = getattr(adapter, "normalize", None)
        pack = self.packs.get(run["policy_version"])
        try:
            prepared = prepare(output.raw)
        except IngestRejected as exc:
            with tenant_connection(self.engine, tenant) as conn:
                self._finish_if_owner(conn, task, "FAILED", errors=[f"INGEST_REJECTED:{exc.code}"])
            return
        if normalize is None or pack is None:
            with tenant_connection(self.engine, tenant) as conn:
                code = "NO_NORMALIZER" if normalize is None else "POLICY_PACK_UNKNOWN"
                self._finish_if_owner(conn, task, "FAILED", errors=[code])
            return
        batch = normalize(output, run_id=run_id, task_id=str(task["task_id"]))
        now = self.clock()
        warnings = [*output.warnings, *gw_warnings]
        with tenant_connection(self.engine, tenant) as conn:
            if not self._owns(conn, task):
                return  # lease lost while the tool ran: another worker owns this task now
            ref = evidence_ref(
                tenant, project, run_id, task["adapter_id"], str(task["task_id"]), "raw"
            )
            art = store_evidence(
                conn, self.evidence, prepared, tenant_id=tenant, project_id=project,
                run_id=run_id, task_id=str(task["task_id"]), ref=ref, source=task["adapter_id"],
                tool_version=f"{output.tool}@{output.tool_version}", collected_at=output.collected_at,
            )  # fmt: skip
            expected = set(task["expected_assets"])
            warnings.extend(batch.warnings)
            known = [
                KnownAsset(r[0], r[1], r[2])
                for r in conn.execute(
                    text(
                        "SELECT asset_id, native_ids->>'ip', native_ids->>'hostname' "
                        "FROM assets WHERE project_id=:p"
                    ),
                    {"p": project},
                )
            ]
            keymap: dict[str, str] = {}
            attrs: dict[str, dict[str, Any]] = {}  # final asset id -> merged attributes
            for a in batch.assets:
                final = a.asset_id
                confidence = "HIGH" if a.asset_id in expected else "LOW"
                if (
                    a.identity
                ):  # scanner-style host: attach to a canonical asset only if unambiguous
                    ident = a.identity.get("ip") or a.identity.get("hostname") or a.asset_id
                    res = resolve_identity(
                        known, ip=a.identity.get("ip"), hostname=a.identity.get("hostname")
                    )
                    if res.status == "MATCHED" and res.asset_id:
                        final = res.asset_id
                        # HIGH/MEDIUM only for members of the authoritative inventory. Scanners that
                        # agree with each other about an unknown host do not make it a known asset.
                        confidence = res.confidence if final in expected else "LOW"
                    elif res.status == "AMBIGUOUS":
                        warnings.append(f"AMBIGUOUS_IDENTITY:{ident}:{res.reason}")
                keymap[a.asset_id] = final
                existing = conn.execute(
                    text("SELECT attrs FROM assets WHERE project_id=:p AND asset_id=:a"),
                    {"p": project, "a": final},
                ).scalar()
                attrs[final] = {**(existing or {}), **a.attrs}
                native = {
                    **(a.native_ids or {"fixture": a.asset_id, "hostname": a.hostname}),
                    **(a.identity or {}),
                }
                conn.execute(
                    text(
                        "INSERT INTO assets (tenant_id, project_id, asset_id, run_id, asset_type, "
                        "native_ids, technology, attrs, first_seen, last_seen, match_confidence, "
                        "owner, owner_source, criticality, criticality_source, environment) VALUES "
                        "(:t, :p, :a, :r, :atype, CAST(:n AS jsonb), :tech, CAST(:attrs AS jsonb), "
                        ":ts, :ts, :mc, :o, :os, :c, :cs, :env) "
                        "ON CONFLICT (tenant_id, project_id, asset_id) DO UPDATE SET "
                        "last_seen=EXCLUDED.last_seen, run_id=EXCLUDED.run_id, "
                        "technology=COALESCE(EXCLUDED.technology, assets.technology), "
                        "attrs=assets.attrs || EXCLUDED.attrs, "
                        "native_ids=assets.native_ids || EXCLUDED.native_ids, "
                        "owner=COALESCE(EXCLUDED.owner, assets.owner), "
                        "owner_source=COALESCE(EXCLUDED.owner_source, assets.owner_source), "
                        "criticality=COALESCE(EXCLUDED.criticality, assets.criticality), "
                        "criticality_source=COALESCE(EXCLUDED.criticality_source, assets.criticality_source), "
                        "environment=COALESCE(EXCLUDED.environment, assets.environment), "
                        "match_confidence=CASE WHEN assets.match_confidence='HIGH' THEN 'HIGH' "
                        "ELSE EXCLUDED.match_confidence END"
                    ),
                    {
                        "t": tenant, "p": project, "a": final, "r": run_id,
                        "n": json.dumps(native), "atype": a.asset_type, "attrs": json.dumps(a.attrs),
                        "tech": a.attrs.get("os_family"), "ts": output.collected_at, "mc": confidence,
                        "o": a.owner, "os": a.owner_source if a.owner else None,
                        "c": a.criticality, "cs": a.criticality_source if a.criticality else None,
                        "env": a.environment,
                    },
                )  # fmt: skip
                conn.execute(
                    text(
                        "INSERT INTO run_asset_status (tenant_id, run_id, task_id, segment, "
                        "asset_id, status, reason) VALUES (:t, :r, :k, :s, :a, :st, :re) "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {
                        "t": tenant, "r": run_id, "k": task["task_id"], "s": task["target_selector"],
                        "a": final, "st": a.status, "re": redact_obj(a.reason),
                    },
                )  # fmt: skip
            n_obs = 0
            for o in batch.observations:
                asset_id = keymap.get(o.asset_id, o.asset_id)
                outcome = self.evaluator.evaluate_observation(
                    pack, rule_id=o.rule_id, value=o.value, attrs=attrs.get(asset_id, {})
                )
                if outcome is None:
                    warnings.append(f"UNMODELLED_OBSERVATION:{o.rule_id}")
                    continue
                rule = pack.rule(o.rule_id)
                conn.execute(
                    text(
                        "INSERT INTO observations (tenant_id, run_id, observation_id, asset_id, "
                        "source, rule_id, observed_value, expected_value, outcome, observed_at, "
                        "evidence_ref, tool_version) VALUES (:t, :r, :o, :a, :s, :rule, "
                        "CAST(:v AS jsonb), CAST(:e AS jsonb), :out, :at, :ref, :tv) "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {
                        "t": tenant, "r": run_id, "o": o.observation_id, "a": asset_id,
                        "s": task["adapter_id"], "rule": o.rule_id,
                        "v": json.dumps(redact_obj(o.value)),
                        "e": json.dumps(rule.check.value if rule else None),
                        "out": outcome.value, "at": output.collected_at, "ref": ref,
                        "tv": art.tool_version,
                    },
                )  # fmt: skip
                n_obs += 1
            status = output.status
            if status == "SUCCEEDED" and not batch.assets:
                status = "PARTIAL"
                warnings.append("ZERO_ASSETS_RETURNED")  # tool "success" with no assets: anomaly
            append_event(
                conn, tenant_id=tenant, run_id=run_id, now=now, event_type="evidence.batch.stored",
                payload={"source_id": task["adapter_id"], "asset_count": len(batch.assets),
                         "observation_count": n_obs, "evidence_refs_count": 1,
                         "hash_manifest_ref": art.content_hash},
            )  # fmt: skip
            self._finish(
                conn,
                task,
                status,
                warnings=warnings,
                errors=list(output.errors),
                output_refs=[ref],
                tool_version=art.tool_version,
            )

    # ------------------------------------------------------------------ task completion
    def _finish(
        self,
        conn: Connection,
        task: dict[str, Any],
        status: str,
        *,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        output_refs: list[str] | None = None,
        tool_version: str | None = None,
    ) -> None:
        now = self.clock()
        warnings = redact_obj(warnings or [])
        errors = redact_obj(errors or [])
        conn.execute(
            text(
                "UPDATE run_tasks SET status=:s, completed_at=:n, locked_by=NULL, locked_until=NULL, "
                "warnings=CAST(:w AS jsonb), errors=CAST(:e AS jsonb), "
                "output_refs=CAST(:o AS jsonb), tool_version=COALESCE(:tv, tool_version) "
                "WHERE task_id=:t"
            ),
            {
                "s": status, "n": now, "w": json.dumps(warnings), "e": json.dumps(errors),
                "o": json.dumps(output_refs or []), "tv": tool_version, "t": task["task_id"],
            },
        )  # fmt: skip
        event = {"SUCCEEDED": "task.completed", "PARTIAL": "task.partial"}.get(
            status, "task.failed"
        )
        append_event(
            conn, tenant_id=task["tenant_id"], run_id=task["run_id"], now=now, event_type=event,
            payload={"task_id": str(task["task_id"]), "status": status,
                     "warning_codes": warnings[:20], "error_codes": errors[:20],
                     "output_refs": output_refs or []},
        )  # fmt: skip

    # ------------------------------------------------------------------ run advancement
    def advance_one(self) -> bool:
        with self.engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT run_id, tenant_id FROM assessment_runs WHERE state = ANY(:s) "
                    "ORDER BY created_at LIMIT 50"
                ),
                {"s": list(ADVANCEABLE)},
            ).all()
        return any(self._advance(r[1], r[0]) for r in rows)

    def _run(self, conn: Connection, run_id: str, *, lock: bool = False) -> dict[str, Any]:
        sql = _SELECT_RUN_LOCKED if lock else _SELECT_RUN
        return dict(conn.execute(text(sql), {"r": run_id}).mappings().one())

    def _set_state(
        self, conn: Connection, run: dict[str, Any], new: str, *, reason: str | None = None,
        partial: bool | None = None,
    ) -> None:  # fmt: skip
        now = self.clock()
        terminal = new in {"FAILED", "CANCELLED", "PARTIAL", "CLOSED", "EXPIRED"}
        n = conn.execute(
            text(
                "UPDATE assessment_runs SET state=:new, last_phase=:lp, reason=:re, "
                "partial=COALESCE(:pa, partial), updated_at=:n WHERE run_id=:r AND state=:old"
            ),
            {
                "new": new, "lp": run["state"] if terminal else new, "re": reason, "pa": partial,
                "n": now, "r": run["run_id"], "old": run["state"],
            },
        ).rowcount  # fmt: skip
        if n != 1:
            raise RuntimeError("run state changed concurrently")
        append_event(
            conn, tenant_id=run["tenant_id"], run_id=run["run_id"], now=now,
            event_type="phase.changed",
            payload={"from": run["state"], "to": new, "reason": reason},
        )  # fmt: skip
        run["state"] = new

    def _advance(self, tenant: str, run_id: str) -> bool:
        with tenant_connection(self.engine, tenant) as conn:
            run = self._run(conn, run_id, lock=True)
            state = run["state"]
            if state == "AUTHORIZED":
                self._set_state(conn, run, "ASSESSMENT_DISPATCH")
                return True
            if state == "ASSESSMENT_DISPATCH":
                return self._after_dispatch(conn, run)
            if state == "POLICY_EVALUATION":
                self._policy_phase(conn, run)
                self._set_state(conn, run, "ASSURANCE")
                return True
            if state == "ASSURANCE":
                self._assurance_phase(conn, run)
                self._report_phase(conn, run)
                return True
        return False

    def _after_dispatch(self, conn: Connection, run: dict[str, Any]) -> bool:
        tasks = conn.execute(
            text("SELECT status FROM run_tasks WHERE run_id=:r"), {"r": run["run_id"]}
        ).all()
        statuses = [t[0] for t in tasks]
        if not statuses:
            self._set_state(conn, run, "FAILED", reason="NO_TASKS")
            return True
        if any(s in {"QUEUED", "RUNNING"} for s in statuses):
            return False
        if run["cancel_requested"]:
            self._set_state(conn, run, "CANCELLED", reason="CANCEL_REQUESTED")
            append_event(
                conn, tenant_id=run["tenant_id"], run_id=run["run_id"], now=self.clock(),
                event_type="assessment.cancelled",
                payload={"final_status": "CANCELLED", "remaining_tasks": 0,
                         "reason": "CANCEL_REQUESTED", "time": self.clock().isoformat()},
            )  # fmt: skip
            return True
        if not any(s in {"SUCCEEDED", "PARTIAL"} for s in statuses):
            self._set_state(conn, run, "FAILED", reason="ALL_TASKS_FAILED")
            return True
        partial = any(s != "SUCCEEDED" for s in statuses)
        self._set_state(conn, run, "POLICY_EVALUATION", partial=partial)
        return True

    # ---- policy evaluation: controls, findings, coverage (deterministic) -------------------
    def _policy_phase(self, conn: Connection, run: dict[str, Any]) -> None:
        tenant, project, run_id = run["tenant_id"], str(run["project_id"]), run["run_id"]
        pack = self.packs.get(run["policy_version"])
        if pack is None:
            raise RuntimeError("policy pack disappeared")
        tasks = (
            conn.execute(
                text(
                    "SELECT * FROM run_tasks WHERE run_id=:r "
                    "AND status IN ('SUCCEEDED','PARTIAL') ORDER BY created_at"
                ),
                {"r": run_id},
            )
            .mappings()
            .all()
        )  # fmt: skip
        status_rows = conn.execute(
            text(
                "SELECT s.task_id, s.asset_id, s.status, s.reason, a.attrs "
                "FROM run_asset_status s LEFT JOIN assets a ON a.asset_id = s.asset_id "
                "AND a.project_id=:p WHERE s.run_id=:r"
            ),
            {"r": run_id, "p": project},
        ).all()
        obs = {
            (r[0], r[1]): r
            for r in conn.execute(
                text(
                    "SELECT asset_id, rule_id, outcome, observation_id, evidence_ref, "
                    "observed_value, observed_at FROM observations WHERE run_id=:r"
                ),
                {"r": run_id},
            ).all()
        }
        results: list[RuleResult] = []
        asset_results: dict[str, list[PolicyOutcome]] = {}
        seen_assets: set[str] = set()
        for _task_id, asset_id, status, _reason, attrs in status_rows:
            if status != "SCANNED" or asset_id in seen_assets:
                continue
            seen_assets.add(asset_id)
            for rule in self.evaluator.applicable_rules(pack, attrs or {}):
                o = obs.get((asset_id, rule.rule_id))
                if o is None:
                    res = RuleResult(asset_id, rule, PolicyOutcome.NOT_ASSESSED, None, None)
                else:
                    res = RuleResult(asset_id, rule, PolicyOutcome(o[2]), o[3], o[4], o[5])
                results.append(res)
                asset_results.setdefault(asset_id, []).append(res.outcome)

        # controls
        for ctrl in sorted({r.control_id for r in pack.rules}):
            cr = [x for x in results if x.rule.control_id == ctrl]
            outcome = rollup(x.outcome for x in cr)
            refs = sorted({x.evidence_ref for x in cr if x.evidence_ref and
                           x.outcome in {PolicyOutcome.PASS, PolicyOutcome.FAIL}})  # fmt: skip
            conn.execute(
                text(
                    "INSERT INTO control_assessments (tenant_id, run_id, framework, version, "
                    "control_id, applicability, outcome, evidence_refs, policy_version) VALUES "
                    "(:t, :r, :f, :v, :c, :ap, :o, CAST(:e AS jsonb), :pv) ON CONFLICT DO NOTHING"
                ),
                {
                    "t": tenant, "r": run_id, "f": pack.framework.name, "v": pack.framework.version,
                    "c": ctrl, "ap": "NOT_APPLICABLE" if not cr else "APPLICABLE",
                    "o": outcome.value, "e": json.dumps(refs), "pv": pack.key,
                },
            )  # fmt: skip

        # findings (FAIL only; PASS is never a finding)
        for res in results:
            if res.outcome is not PolicyOutcome.FAIL or res.evidence_ref is None:
                continue
            o = obs[(res.asset_id, res.rule.rule_id)]
            mappings = [
                ControlMapping(
                    framework=pack.framework.name,
                    version=pack.framework.version,
                    control_id=res.rule.control_id,
                    mapping_status="APPROVED",
                ),
                *res.rule.mappings,
            ]
            f = Finding(
                finding_id=finding_id(pack, res.rule.rule_id, res.asset_id),
                stable_dedupe_key=dedupe_key(pack, res.rule.rule_id, res.asset_id),
                tenant_id=tenant, project_id=project, run_id=run_id, title=res.rule.title,
                category=res.rule.category, severity=res.rule.severity,
                severity_source=f"policy:{pack.key}", confidence="MEDIUM",
                outcome=PolicyOutcome.FAIL, affected_assets=[res.asset_id],
                evidence_refs=[res.evidence_ref], control_mappings=mappings,
                assumptions=["Runtime exposure and business impact are not verified"],
                policy_version=pack.key, first_observed=o[6], last_observed=o[6],
            )  # fmt: skip
            conn.execute(
                text(
                    "INSERT INTO findings (tenant_id, run_id, finding_id, stable_dedupe_key, "
                    "project_id, severity, outcome, body) VALUES (:t, :r, :f, :k, :p, :s, :o, "
                    "CAST(:b AS jsonb)) ON CONFLICT DO NOTHING"
                ),
                {
                    "t": tenant, "r": run_id, "f": f.finding_id, "k": f.stable_dedupe_key,
                    "p": project, "s": f.severity.value, "o": f.outcome.value,
                    "b": json.dumps(f.model_dump(mode="json")),
                },
            )  # fmt: skip

        # coverage ledger per task segment
        for t in tasks:
            seg_rows = [r for r in status_rows if r[0] == t["task_id"]]
            statuses = {r[1]: (r[2], r[3]) for r in seg_rows}
            outcomes = {a: rollup(asset_results.get(a, [])) for a in statuses}
            ledger = build_ledger(
                tenant_id=tenant, run_id=run_id, segment=f"{t['target_selector']} [{t['adapter_id']}]",
                expected=list(t["expected_assets"]), statuses=statuses, asset_outcomes=outcomes,
                source_ok=t["status"] in {"SUCCEEDED", "PARTIAL"},
                source_reasons=(
                    [f"TASK_{t['status']}"] if t["status"] != "SUCCEEDED" else []
                ) + [w for w in t["warnings"] if str(w).split(":")[0] in GAP_PREFIXES],
                last_success_at=t["completed_at"],
            )  # fmt: skip
            conn.execute(
                text(
                    "INSERT INTO coverage_ledger (tenant_id, run_id, segment, body) VALUES "
                    "(:t, :r, :s, CAST(:b AS jsonb)) ON CONFLICT DO NOTHING"
                ),
                {"t": tenant, "r": run_id, "s": ledger.segment,
                 "b": json.dumps(ledger.model_dump(mode="json"))},
            )  # fmt: skip

    # ---- assurance ------------------------------------------------------------------------
    def _assurance_phase(self, conn: Connection, run: dict[str, Any]) -> None:
        tenant, project, run_id = run["tenant_id"], str(run["project_id"]), run["run_id"]
        pack = self.packs.get(run["policy_version"])
        if pack is None:
            raise RuntimeError("policy pack disappeared")
        cache: dict[str, ArtifactMeta | None] = {}

        def artifact(ref: str) -> ArtifactMeta | None:
            if ref not in cache:
                r = conn.execute(
                    text(
                        "SELECT tenant_id, project_id::text, run_id, content_hash, collected_at "
                        "FROM evidence_artifacts WHERE tenant_id=:t AND evidence_ref=:ref"
                    ),
                    {"t": tenant, "ref": ref},
                ).first()
                cache[ref] = ArtifactMeta(*r) if r else None
            return cache[ref]

        def asset_exists(asset_id: str) -> bool:
            return (
                conn.execute(
                    text("SELECT 1 FROM assets WHERE project_id=:p AND asset_id=:a"),
                    {"p": project, "a": asset_id},
                ).first()
                is not None
            )

        ctx = AssuranceContext(
            tenant_id=tenant, project_id=project, run_id=run_id, policy_version=pack.key,
            pack_control_ids=frozenset(pack.control_ids()), pack_framework=pack.framework.name,
            now=self.clock(), freshness=self.freshness, artifact=artifact,
            evidence_ok=lambda m: self.evidence.verify(m.tenant_id, m.content_hash),
            asset_exists=asset_exists,
        )  # fmt: skip
        rows = conn.execute(
            text("SELECT finding_id, body FROM findings WHERE run_id=:r ORDER BY finding_id"),
            {"r": run_id},
        ).all()
        for fid, body in rows:
            res = assess_finding(Finding.model_validate(body), ctx)
            conn.execute(
                text(
                    "INSERT INTO assurance_results (tenant_id, run_id, item_ref, verdict, "
                    "defect_codes, missing_refs, stale_refs, validation_version, validated_at) "
                    "VALUES (:t, :r, :i, :v, CAST(:d AS jsonb), CAST(:m AS jsonb), "
                    "CAST(:s AS jsonb), :ver, :at) ON CONFLICT DO NOTHING"
                ),
                {
                    "t": tenant, "r": run_id, "i": res.item_ref, "v": res.verdict.value,
                    "d": json.dumps(res.defect_codes), "m": json.dumps(res.missing_refs),
                    "s": json.dumps(res.stale_refs), "ver": res.validation_version,
                    "at": res.validated_at,
                },
            )  # fmt: skip
            conn.execute(
                text("UPDATE findings SET assurance_verdict=:v WHERE run_id=:r AND finding_id=:f"),
                {"v": res.verdict.value, "r": run_id, "f": fid},
            )

    # ---- report ---------------------------------------------------------------------------
    def _report_phase(self, conn: Connection, run: dict[str, Any]) -> None:
        from aisw.contracts.domain import CoverageLedger

        tenant, project, run_id = run["tenant_id"], str(run["project_id"]), run["run_id"]
        pack = self.packs.get(run["policy_version"])
        if pack is None:
            raise RuntimeError("policy pack disappeared")
        manifest_version = conn.execute(
            text("SELECT version FROM scope_manifests WHERE manifest_id=:m"),
            {"m": run["manifest_id"]},
        ).scalar_one()
        tasks = [
            {
                "task_id": str(r["task_id"]),
                "adapter_id": r["adapter_id"],
                "target": r["target_selector"],
                "status": r["status"],
                "warnings": r["warnings"],
                "errors": r["errors"],
                "tool_version": r["tool_version"],
            }
            for r in conn.execute(
                text("SELECT * FROM run_tasks WHERE run_id=:r ORDER BY created_at, task_id"),
                {"r": run_id},
            ).mappings()
        ]
        ledgers = [
            CoverageLedger.model_validate(b)
            for (b,) in conn.execute(
                text("SELECT body FROM coverage_ledger WHERE run_id=:r ORDER BY segment"),
                {"r": run_id},
            )
        ]
        controls = [
            {"framework": f, "version": v, "control_id": c, "applicability": a, "outcome": o,
             "evidence_refs": e}
            for f, v, c, a, o, e in conn.execute(
                text(
                    "SELECT framework, version, control_id, applicability, outcome, evidence_refs "
                    "FROM control_assessments WHERE run_id=:r ORDER BY control_id"
                ),
                {"r": run_id},
            )
        ]  # fmt: skip
        accepted, needs_review, rejected = [], [], 0
        for _fid, verdict, body in conn.execute(
            text("SELECT finding_id, assurance_verdict, body FROM findings WHERE run_id=:r "
                 "ORDER BY finding_id"),
            {"r": run_id},
        ):  # fmt: skip
            if verdict == "ACCEPT":
                accepted.append(body)
            elif verdict == "NEEDS_REVIEW":
                needs_review.append({"finding_id": body["finding_id"], "severity": body["severity"],
                                     "title": body["title"]})  # fmt: skip
            else:
                rejected += 1  # REJECT or never assessed: never authoritative
        evidence = [
            {"ref": r, "hash": h}
            for r, h in conn.execute(
                text("SELECT evidence_ref, content_hash FROM evidence_artifacts WHERE run_id=:r"),
                {"r": run_id},
            )
        ]
        now = self.clock()
        bundle, body, html = build_report(
            ReportInputs(
                tenant_id=tenant, project_id=project, run_id=run_id,
                manifest_hash=run["manifest_hash"], manifest_version=manifest_version,
                policy_version=pack.key, pack_hash=pack.pack_hash, tasks=tasks, ledgers=ledgers,
                controls=controls, accepted=accepted, needs_review=needs_review,
                rejected_count=rejected, evidence=evidence, run_partial=run["partial"],
                generated_at=now, notice=pack.report_notice,
            )
        )  # fmt: skip
        conn.execute(
            text(
                "INSERT INTO reports (report_id, tenant_id, project_id, run_id, body, html, "
                "report_hash, generated_at) VALUES (:id, :t, :p, :r, CAST(:b AS jsonb), :h, :rh, "
                ":n) ON CONFLICT (run_id) DO NOTHING"
            ),
            {"id": bundle.report_id, "t": tenant, "p": project, "r": run_id,
             "b": json.dumps(body), "h": html, "rh": bundle.report_hash, "n": now},
        )  # fmt: skip
        partial = run["partial"] or not bundle.coverage_complete
        append_event(
            conn, tenant_id=tenant, run_id=run_id, now=now,
            event_type="report.partial" if partial else "report.ready",
            payload={"report_id": bundle.report_id,
                     "coverage_summary": {"complete": bundle.coverage_complete},
                     "limitations": bundle.limitations[:20], "report_hash": bundle.report_hash},
        )  # fmt: skip
        self._set_state(
            conn,
            run,
            "PARTIAL" if partial else "REPORT_READY",
            reason="PARTIAL_COVERAGE" if partial else None,
            partial=partial,
        )
        append_audit(
            conn, tenant_id=tenant, actor="orchestrator", action="report.generate",
            resource=f"report:{bundle.report_id}", result="SUCCESS", correlation_id=run_id,
            after_hash=canonical_hash({"report_hash": bundle.report_hash}),
        )  # fmt: skip


__all__ = ["Worker", "PolicyPack"]
