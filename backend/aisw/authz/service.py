"""Manifest and permit lifecycle persisted in PostgreSQL (tenant RLS, audit in the same txn).

create_draft -> preflight -> approve (sign) -> authorize_launch (idempotent, issues permit).
Every denial is audited in its own transaction (a denied action leaves a DENIED event even though
its work rolled back). No tool is ever called from here.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, Engine, text

from aisw.authz.gate import Approval, GateOutcome, ScopeGate
from aisw.authz.signing import KeyRing, ManifestSigner, signing_payload
from aisw.contracts.base import canonical_hash
from aisw.contracts.enums import Decision, ManifestStatus
from aisw.contracts.manifest import ExecutionPermit, ScopeManifest, ScopeManifestBody
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.idempotency import run_idempotent
from aisw.core.rbac import ActorContext, Forbidden, Permission, authorize


class ScopeDenied(Exception):
    """Carries stable reason codes; mapped to HTTP 403/422 by the API layer (M3)."""

    def __init__(self, reason_codes: list[str], outcome: GateOutcome | None = None) -> None:
        super().__init__(",".join(reason_codes))
        self.reason_codes = reason_codes
        self.outcome = outcome


@dataclass(frozen=True)
class LaunchAuthorization:
    run_id: str
    permit: ExecutionPermit
    replayed: bool


Clock = Callable[[], datetime]
AuthorizedHook = Callable[[Connection, str, ExecutionPermit, ScopeManifest], None]
_SELECT_MANIFEST = "SELECT * FROM scope_manifests WHERE manifest_id=:m"
_SELECT_MANIFEST_LOCKED = _SELECT_MANIFEST + " FOR UPDATE"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def row_to_manifest(row: Any) -> ScopeManifest:
    return ScopeManifest.model_validate(
        {
            "manifest_id": str(row["manifest_id"]),
            "version": row["version"],
            "status": row["status"],
            "body": row["body"],
            "canonical_hash": row["canonical_hash"],
            "signature": row["signature"],
            "key_id": row["key_id"],
            "created_by": row["created_by"],
            "approved_by": tuple(row["approved_by"] or ()),
        }
    )


def row_to_permit(row: Any) -> ExecutionPermit:
    return ExecutionPermit.model_validate(
        {
            "permit_id": str(row["permit_id"]),
            "tenant_id": row["tenant_id"],
            "project_id": str(row["project_id"]),
            "run_id": row["run_id"],
            "manifest_hash": row["manifest_hash"],
            "allowed_task_types": list(row["allowed_task_types"]),
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "policy_version": row["policy_version"],
        }
    )


class ScopeService:
    def __init__(
        self,
        *,
        engine: Engine,
        gate: ScopeGate,
        signer: ManifestSigner,
        keyring: KeyRing,
        clock: Clock = _utcnow,
    ) -> None:
        self.engine = engine
        self.gate = gate
        self.signer = signer
        self.keyring = keyring
        self.clock = clock

    # -- helpers ---------------------------------------------------------------------------
    def _audit_denied(
        self, actor: ActorContext, action: str, resource: str, cid: str, codes: list[str]
    ) -> None:
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action=action,
                resource=resource, result="DENIED", correlation_id=cid,
                after_hash=canonical_hash({"reasons": codes}),
            )  # fmt: skip

    def _project_known(self, conn: Connection, project_id: str) -> bool:
        try:
            uuid.UUID(project_id)
        except ValueError:
            return False
        return (
            conn.execute(
                text("SELECT 1 FROM projects WHERE project_id=:p"), {"p": project_id}
            ).first()
            is not None
        )

    def _load(self, conn: Connection, manifest_id: str, *, lock: bool = False) -> ScopeManifest:
        try:
            uuid.UUID(manifest_id)
        except ValueError as exc:
            raise ScopeDenied(["MANIFEST_NOT_FOUND"]) from exc
        sql = _SELECT_MANIFEST_LOCKED if lock else _SELECT_MANIFEST
        row = conn.execute(text(sql), {"m": manifest_id}).mappings().first()
        if row is None:  # also the answer for another tenant's manifest (RLS)
            raise ScopeDenied(["MANIFEST_NOT_FOUND"])
        return row_to_manifest(row)

    # -- lifecycle -------------------------------------------------------------------------
    def create_draft(
        self, actor: ActorContext, project_id: str, body: ScopeManifestBody, *, cid: str
    ) -> tuple[ScopeManifest, GateOutcome]:
        """Resolve and validate the draft; persist only if nothing blocks it."""
        authorize_or_audit = self._authorize(
            actor, Permission.MANIFEST_CREATE, "manifest.create", cid
        )
        authorize_or_audit()
        now = self.clock()
        denial: ScopeDenied | None = None
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            outcome = self.gate.evaluate(
                actor=actor, project_id=project_id, body=body, requested_by=actor.actor_id,
                now=now, project_known=self._project_known(conn, project_id),
            )  # fmt: skip
            if outcome.decision.decision is Decision.DENY:
                denial = ScopeDenied(outcome.decision.reason_codes, outcome)
            else:
                version = conn.execute(
                    text(
                        "SELECT COALESCE(MAX(version),0)+1 FROM scope_manifests WHERE project_id=:p"
                    ),
                    {"p": project_id},
                ).scalar_one()
                row = (
                    conn.execute(
                        text(
                            "INSERT INTO scope_manifests (tenant_id, project_id, version, status, "
                            "body, canonical_hash, created_by) VALUES (:t, :p, :v, 'DRAFT', "
                            "CAST(:b AS jsonb), :h, :by) RETURNING *"
                        ),
                        {
                            "t": actor.tenant_id, "p": project_id, "v": version,
                            "b": json.dumps(outcome.body.model_dump(mode="json")),
                            "h": outcome.body.hash(), "by": actor.actor_id,
                        },
                    )
                    .mappings()
                    .one()
                )  # fmt: skip
                manifest = row_to_manifest(row)
                append_audit(
                    conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
                    action="manifest.create", resource=f"manifest:{manifest.manifest_id}",
                    result="SUCCESS", correlation_id=cid, after_hash=manifest.canonical_hash,
                )  # fmt: skip
        if denial is not None:
            self._audit_denied(
                actor, "manifest.create", f"project:{project_id}", cid, denial.reason_codes
            )
            raise denial
        return manifest, outcome

    def preflight(self, actor: ActorContext, manifest_id: str, *, cid: str) -> GateOutcome:
        self._authorize(actor, Permission.MANIFEST_CREATE, "manifest.preflight", cid)()
        denial: ScopeDenied | None = None
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            try:
                m = self._load(conn, manifest_id, lock=True)
            except ScopeDenied as exc:
                denial = exc
            else:
                outcome = self.gate.evaluate(
                    actor=actor, project_id=m.body.project_id, body=m.body,
                    requested_by=m.created_by, now=self.clock(),
                    project_known=self._project_known(conn, m.body.project_id),
                    require_requester_permission=False,
                )  # fmt: skip
                drift = outcome.body.hash() != m.canonical_hash  # inventory changed since draft
                if drift or outcome.decision.decision is Decision.DENY:
                    codes = outcome.decision.reason_codes + (["INVENTORY_DRIFT"] if drift else [])
                    denial = ScopeDenied(codes, outcome)
                elif m.status in {ManifestStatus.DRAFT, ManifestStatus.PREFLIGHTED}:
                    conn.execute(
                        text(
                            "UPDATE scope_manifests SET status='PREFLIGHTED' WHERE manifest_id=:m"
                        ),
                        {"m": manifest_id},
                    )
                    append_audit(
                        conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
                        action="manifest.preflight", resource=f"manifest:{manifest_id}",
                        result="SUCCESS", correlation_id=cid, after_hash=m.canonical_hash,
                    )  # fmt: skip
                    return outcome
                else:
                    denial = ScopeDenied(["MANIFEST_NOT_PREFLIGHTABLE"], outcome)
        if denial is None:  # unreachable: every path above returns or sets denial
            raise RuntimeError("gate finished without outcome")
        self._audit_denied(
            actor, "manifest.preflight", f"manifest:{manifest_id}", cid, denial.reason_codes
        )
        raise denial

    def approve(
        self,
        actor: ActorContext,
        manifest_id: str,
        *,
        acknowledge_active_adapters: frozenset[str] = frozenset(),
        cid: str,
    ) -> ScopeManifest:
        self._authorize(actor, Permission.MANIFEST_APPROVE, "manifest.approve", cid)()
        denial: ScopeDenied | None = None
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            try:
                m = self._load(conn, manifest_id, lock=True)
                if m.status is not ManifestStatus.PREFLIGHTED:
                    raise ScopeDenied(["MANIFEST_NOT_PREFLIGHTED"])
                if m.created_by == actor.actor_id:
                    raise ScopeDenied(["SELF_APPROVAL"])
                outcome = self.gate.evaluate(
                    actor=actor, project_id=m.body.project_id, body=m.body,
                    requested_by=m.created_by, now=self.clock(),
                    approvals=[Approval(actor.actor_id, True, acknowledge_active_adapters)],
                    project_known=self._project_known(conn, m.body.project_id),
                    require_requester_permission=False,
                )  # fmt: skip
                if outcome.body.hash() != m.canonical_hash:
                    raise ScopeDenied(["INVENTORY_DRIFT"], outcome)
                if outcome.decision.decision is not Decision.ALLOW:
                    raise ScopeDenied(outcome.decision.reason_codes, outcome)
                payload = signing_payload(
                    tenant_id=m.body.tenant_id, project_id=m.body.project_id,
                    manifest_id=m.manifest_id, version=m.version, canonical_hash=m.canonical_hash,
                )  # fmt: skip
                signature = self.signer.sign(payload)
                conn.execute(
                    text(
                        "UPDATE scope_manifests SET status='SUPERSEDED' WHERE project_id=:p "
                        "AND status='APPROVED' AND manifest_id<>:m"
                    ),
                    {"p": m.body.project_id, "m": manifest_id},
                )
                row = (
                    conn.execute(
                        text(
                            "UPDATE scope_manifests SET status='APPROVED', signature=:s, "
                            "key_id=:k, approved_by=ARRAY[:a] WHERE manifest_id=:m RETURNING *"
                        ),
                        {"s": signature, "k": self.signer.key_id, "a": actor.actor_id,
                         "m": manifest_id},
                    )
                    .mappings()
                    .one()
                )  # fmt: skip
                approved = row_to_manifest(row)
                append_audit(
                    conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
                    action="manifest.approve", resource=f"manifest:{manifest_id}",
                    result="SUCCESS", correlation_id=cid, before_hash=m.canonical_hash,
                    after_hash=canonical_hash({"hash": m.canonical_hash, "signature": signature}),
                )  # fmt: skip
                return approved
            except ScopeDenied as exc:
                denial = exc
        if denial is None:  # unreachable: every path above returns or sets denial
            raise RuntimeError("gate finished without outcome")
        self._audit_denied(
            actor, "manifest.approve", f"manifest:{manifest_id}", cid, denial.reason_codes
        )
        raise denial

    def revoke_manifest(self, actor: ActorContext, manifest_id: str, *, cid: str) -> None:
        self._authorize(actor, Permission.MANIFEST_APPROVE, "manifest.revoke", cid)()
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            m = self._load(conn, manifest_id, lock=True)
            conn.execute(
                text("UPDATE scope_manifests SET status='REVOKED' WHERE manifest_id=:m"),
                {"m": manifest_id},
            )
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="manifest.revoke",
                resource=f"manifest:{manifest_id}", result="SUCCESS", correlation_id=cid,
                before_hash=m.canonical_hash,
            )  # fmt: skip

    # -- launch authorisation (Agent 0 at execution time) ------------------------------------
    def authorize_launch(
        self,
        actor: ActorContext,
        *,
        project_id: str,
        manifest_id: str,
        manifest_hash: str,
        task_types: list[str] | None,
        idempotency_key: str,
        cid: str,
        on_authorized: AuthorizedHook | None = None,
        request_extra: dict[str, Any] | None = None,
    ) -> LaunchAuthorization:
        self._authorize(actor, Permission.ASSESSMENT_LAUNCH, "assessment.launch", cid)()
        request_body = {
            "project_id": project_id, "manifest_id": manifest_id,
            "manifest_hash": manifest_hash, "task_types": sorted(task_types or []),
            "extra": request_extra or {},
        }  # fmt: skip
        denial: ScopeDenied | None = None
        try:
            with tenant_connection(self.engine, actor.tenant_id) as conn:

                def handler() -> tuple[int, dict[str, Any]]:
                    m = self._load(conn, manifest_id, lock=True)
                    self._check_launchable(actor, conn, m, project_id, manifest_hash, task_types)
                    now = self.clock()
                    run_id = str(uuid.uuid4())
                    allowed = sorted(task_types or m.body.allowed_adapters)
                    ttl = min(self.gate.policy.permit_ttl, m.body.expires_at - now)
                    row = (
                        conn.execute(
                            text(
                                "INSERT INTO execution_permits (tenant_id, project_id, run_id, "
                                "manifest_id, manifest_hash, allowed_task_types, issued_at, "
                                "expires_at, policy_version) VALUES (:t, :p, :r, :m, :h, :a, "
                                ":i, :e, :v) RETURNING *"
                            ),
                            {
                                "t": actor.tenant_id, "p": project_id, "r": run_id,
                                "m": manifest_id, "h": m.canonical_hash, "a": allowed,
                                "i": now, "e": now + ttl, "v": m.body.policy_version,
                            },
                        )
                        .mappings()
                        .one()
                    )  # fmt: skip
                    permit = row_to_permit(row)
                    append_audit(
                        conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
                        action="assessment.authorize", resource=f"run:{run_id}",
                        result="SUCCESS", correlation_id=cid, after_hash=m.canonical_hash,
                    )  # fmt: skip
                    if on_authorized is not None:  # same transaction as the permit
                        on_authorized(conn, run_id, permit, m)
                    return 202, {"run_id": run_id, "permit": permit.model_dump(mode="json")}

                result = run_idempotent(
                    conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
                    scope="POST /assessments", key=idempotency_key,
                    request_body=request_body, handler=handler,
                )  # fmt: skip
        except ScopeDenied as exc:
            denial = exc
        if denial is not None:
            self._audit_denied(
                actor, "assessment.launch", f"manifest:{manifest_id}", cid, denial.reason_codes
            )
            raise denial
        return LaunchAuthorization(
            run_id=result.body["run_id"],
            permit=ExecutionPermit.model_validate(result.body["permit"]),
            replayed=result.replayed,
        )

    def _check_launchable(
        self,
        actor: ActorContext,
        conn: Connection,
        m: ScopeManifest,
        project_id: str,
        manifest_hash: str,
        task_types: list[str] | None,
    ) -> None:
        now = self.clock()
        if m.body.project_id != project_id:
            raise ScopeDenied(["PROJECT_MISMATCH"])
        if m.status is not ManifestStatus.APPROVED:
            raise ScopeDenied(["MANIFEST_NOT_APPROVED"])
        if m.canonical_hash != manifest_hash:
            raise ScopeDenied(["STALE_HASH"])  # request was built against another version
        if m.body.expires_at <= now:
            raise ScopeDenied(["MANIFEST_EXPIRED"])
        if not (m.key_id and m.signature):
            raise ScopeDenied(["BAD_SIGNATURE"])
        payload = signing_payload(
            tenant_id=m.body.tenant_id, project_id=m.body.project_id,
            manifest_id=m.manifest_id, version=m.version, canonical_hash=m.canonical_hash,
        )  # fmt: skip
        if not self.keyring.verify(m.key_id, payload, m.signature):
            raise ScopeDenied(["BAD_SIGNATURE"])
        if task_types is not None and not set(task_types) <= set(m.body.allowed_adapters):
            raise ScopeDenied(["TASK_TYPE_NOT_ALLOWED"])
        # re-run policy at execution time (connector health, DNS, inventory, caps)
        approval = Approval(
            m.approved_by[0], True,
            frozenset(a for a, p in m.body.profiles.items() if p.profile_class.value == "ACTIVE"),
        )  # fmt: skip
        outcome = self.gate.evaluate(
            actor=actor, project_id=project_id, body=m.body, requested_by=m.created_by,
            approvals=[approval], now=now,
            project_known=self._project_known(conn, project_id),
            require_requester_permission=False,
        )  # fmt: skip
        if outcome.body.hash() != m.canonical_hash:
            raise ScopeDenied(["INVENTORY_DRIFT"], outcome)
        if outcome.decision.decision is not Decision.ALLOW:
            raise ScopeDenied(outcome.decision.reason_codes, outcome)

    def revoke_permit(self, actor: ActorContext, permit_id: str, *, cid: str) -> None:
        self._authorize(actor, Permission.ASSESSMENT_CANCEL, "permit.revoke", cid)()
        with tenant_connection(self.engine, actor.tenant_id) as conn:
            n = conn.execute(
                text(
                    "UPDATE execution_permits SET revoked_at=:t "
                    "WHERE permit_id=:p AND revoked_at IS NULL"
                ),
                {"t": self.clock(), "p": permit_id},
            ).rowcount
            if n:
                append_audit(
                    conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="permit.revoke",
                    resource=f"permit:{permit_id}", result="SUCCESS", correlation_id=cid,
                )  # fmt: skip

    def _authorize(
        self, actor: ActorContext, perm: Permission, action: str, cid: str
    ) -> Callable[[], None]:
        def check() -> None:
            try:
                authorize(actor, perm)
            except Forbidden:
                self._audit_denied(actor, action, "authz", cid, ["ROLE_NOT_PERMITTED"])
                raise

        return check
