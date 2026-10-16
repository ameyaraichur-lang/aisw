"""Run creation: turns an authorised launch into a durable run and its queued tasks."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aisw.contracts.manifest import ExecutionPermit, ScopeManifest
from aisw.gateway.registry import AdapterRegistry
from aisw.orchestrator.events import append_event

TERMINAL_TASK = ("SUCCEEDED", "PARTIAL", "FAILED", "REJECTED", "SKIPPED", "CANCELLED", "TIMED_OUT",
                 "NEEDS_REVIEW")  # fmt: skip


def create_run(
    conn: Connection,
    *,
    run_id: str,
    manifest: ScopeManifest,
    permit: ExecutionPermit,
    requested_by: str,
    assessment_profile: str,
    adapter_params: dict[str, dict[str, Any]],
    registry: AdapterRegistry,
    now: datetime,
    ai_mode: str = "disabled",
) -> list[str]:
    """Insert run + tasks + first events atomically. Returns the queued task ids."""
    body = manifest.body
    conn.execute(
        text(
            "INSERT INTO assessment_runs (run_id, tenant_id, project_id, manifest_id, "
            "manifest_hash, permit_id, state, last_phase, requested_by, assessment_profile, "
            "policy_version, created_at, updated_at, ai_mode) VALUES (:r, :t, :p, :m, :h, :permit, "
            "'AUTHORIZED', 'AUTHORIZED', :by, :prof, :pv, :n, :n, :ai)"
        ),
        {
            "r": run_id, "t": body.tenant_id, "p": body.project_id, "m": manifest.manifest_id,
            "h": manifest.canonical_hash, "permit": permit.permit_id, "by": requested_by,
            "prof": assessment_profile, "pv": body.policy_version, "n": now, "ai": ai_mode,
        },
    )  # fmt: skip
    tenant = body.tenant_id
    append_event(
        conn, tenant_id=tenant, run_id=run_id, event_type="assessment.accepted", now=now,
        payload={"actor_ref": requested_by, "manifest_hash": manifest.canonical_hash},
    )  # fmt: skip
    append_event(
        conn, tenant_id=tenant, run_id=run_id, event_type="preflight.completed", now=now,
        payload={"result": "ALLOW", "blockers": [], "warnings": []},
    )  # fmt: skip
    task_ids: list[str] = []
    for target in body.targets:
        for adapter_id in body.allowed_adapters:
            cap = registry.capability(adapter_id)
            if cap is None or target.kind not in cap.target_kinds:
                continue
            expected = (
                conn.execute(
                    text(
                        "SELECT expected_assets FROM inventory_entries WHERE project_id=:p "
                        "AND kind=:k AND selector=:s"
                    ),
                    {"p": body.project_id, "k": target.kind, "s": target.selector},
                ).scalar()
                or []
            )
            task_id = str(
                conn.execute(
                    text(
                        "INSERT INTO run_tasks (tenant_id, run_id, task_type, adapter_id, profile, "
                        "target_kind, target_selector, params, expected_assets, available_at) "
                        "VALUES (:t, :r, :ty, :a, :pr, :k, :s, CAST(:params AS jsonb), "
                        "CAST(:exp AS jsonb), :n) RETURNING task_id"
                    ),
                    {
                        "t": tenant, "r": run_id, "ty": adapter_id, "a": adapter_id,
                        "pr": body.profiles[adapter_id].profile_id, "k": target.kind,
                        "s": target.selector,
                        "params": json.dumps(adapter_params.get(adapter_id, {})),
                        "exp": json.dumps(expected), "n": now,
                    },
                ).scalar_one()
            )  # fmt: skip
            task_ids.append(task_id)
            append_event(
                conn, tenant_id=tenant, run_id=run_id, event_type="task.queued", now=now,
                payload={"task_id": task_id, "agent_id": adapter_id, "domain": sorted(cap.domains),
                         "dependencies": []},
            )  # fmt: skip
    return task_ids
