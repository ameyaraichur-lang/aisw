"""Deployment doctor: ``python -m aisw.doctor [--role api|worker] [--json]`` (ADR-029).

Read-only checks of a configured process before it serves: settings, database role and RLS,
migration head, signing custody, sign-in, evidence storage, AI and egress posture. Makes no model
call and touches no scan target. Exit code: 0 no failures, 1 at least one FAIL, 2 bad settings.
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import ValidationError
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from aisw.authz.signing import SigningError
from aisw.core.config import Environment, ModelProvider, Settings, load_settings
from aisw.core.db import make_engine

Status = Literal["PASS", "WARN", "FAIL"]
MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


def migration_head(migrations: Path = MIGRATIONS) -> str | None:
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations))
    return ScriptDirectory.from_config(cfg).get_current_head()


def _database(engine: Engine, role: str) -> list[Check]:
    out: list[Check] = []
    try:
        with engine.connect() as c:
            user, superuser, bypass = c.execute(text(
                "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )).one()  # fmt: skip
            out.append(Check("database_reachable", "PASS", f"connected as {user}"))
            expected = "aisw_app" if role == "api" else "aisw_worker"
            ok = user == expected and not superuser and not bypass
            out.append(Check("database_role", "PASS" if ok else "FAIL",
                             f"{user} superuser={superuser} bypassrls={bypass}; expected {expected}"))  # fmt: skip
            unforced = c.execute(text(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' "
                "WHERE n.nspname = 'public' AND c.relkind = 'r' "
                "AND NOT (c.relrowsecurity AND c.relforcerowsecurity) ORDER BY 1"
            )).scalars().all()  # fmt: skip
            out.append(Check("row_level_security", "FAIL" if unforced else "PASS",
                             f"not forced on: {', '.join(unforced)}" if unforced
                             else "forced on every tenant table"))  # fmt: skip
            try:
                current = c.execute(text("SELECT version_num FROM alembic_version")).scalar()
            except SQLAlchemyError:
                current = None
            head = migration_head()
            out.append(Check("migrations_at_head", "PASS" if current == head else "FAIL",
                             f"database {current or 'unknown'}, code {head}"))  # fmt: skip
    except SQLAlchemyError as exc:
        out.append(Check("database_reachable", "FAIL", type(exc).__name__))
    return out


def _signing(s: Settings) -> Check:
    if s.signing_backend == "transit":
        from aisw.authz.transit import transit_from_settings  # noqa: PLC0415 - optional backend

        try:
            _, ring = transit_from_settings(s)
        except SigningError as exc:
            return Check("signing_custody", "FAIL", str(exc))
        ids = ring.key_ids()
        return Check("signing_custody", "PASS" if ids else "FAIL",
                     f"transit key versions trusted: {', '.join(ids) or 'none (KMS unreachable?)'}")  # fmt: skip
    if s.env is Environment.PROD:
        return Check("signing_custody", "FAIL", "prod requires AISW_SIGNING_BACKEND=transit")
    path = s.signing_key_path
    if path is None:
        return Check("signing_custody", "WARN", "no signer: manifests cannot be approved")
    if path.exists() and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return Check("signing_custody", "FAIL", "local key file is group/world accessible")
    return Check("signing_custody", "WARN", "local key file (dev/test only)")


def _sign_in(s: Settings) -> Check:
    if s.oidc_enabled:
        from aisw.core.oidc import OidcError, OidcProvider  # noqa: PLC0415 - optional

        try:
            OidcProvider(s).metadata()
        except OidcError as exc:
            return Check("sign_in", "FAIL", f"OIDC discovery failed: {exc}")
        return Check("sign_in", "PASS", f"OIDC issuer {s.oidc_issuer}")
    if s.env is Environment.PROD:
        return Check("sign_in", "FAIL", "prod requires OIDC (AISW_OIDC_ISSUER)")
    return Check("sign_in", "WARN", "dev identity stub only" if s.dev_auth_stub else "no sign-in")


def _evidence(s: Settings) -> Check:
    d = s.evidence_dir
    if d is None:
        return Check(
            "evidence_store", "WARN", "AISW_EVIDENCE_DIR not set: runs cannot store evidence"
        )
    if not d.is_dir():
        return Check("evidence_store", "FAIL", f"{d} does not exist")
    if d.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return Check("evidence_store", "FAIL", f"{d} is group/world accessible")
    probe = d / ".doctor-write-probe"
    try:
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        return Check("evidence_store", "FAIL", f"not writable: {type(exc).__name__}")
    return Check("evidence_store", "PASS", str(d))


def _ai(s: Settings) -> Check:
    if not s.ai_enabled:
        return Check("ai", "PASS", "disabled")
    if s.model_provider is ModelProvider.ASTRA:
        return Check("ai", "WARN", f"Astra deployment {s.model_id}; data approval "
                     f"{s.astra_data_approval_ref!r} (synthetic data only until approved)")  # fmt: skip
    return Check("ai", "PASS", f"local model {s.model_id} at {s.model_endpoint}")


def _egress(s: Settings, role: str) -> Check:
    if role == "worker" and not s.egress_zones:
        status: Status = "WARN" if s.env is not Environment.PROD else "FAIL"
        return Check("egress_scan_zones", status, "AISW_EGRESS_SCAN_CIDRS not set")
    return Check("egress_scan_zones", "PASS", ", ".join(s.egress_zones) or "not used by the API")


def run_checks(s: Settings, role: Literal["api", "worker"], *,
               engine_factory: Callable[[str], Engine] = make_engine) -> list[Check]:  # fmt: skip
    out = [Check("settings", "PASS", f"env={s.env.value} role={role}")]
    if s.env is not Environment.PROD:
        out.append(Check("environment", "WARN", f"env={s.env.value}: not a production deployment"))
    url = s.database_url if role == "api" else s.worker_database_url
    if url is None:
        var = "AISW_DATABASE_URL" if role == "api" else "AISW_WORKER_DATABASE_URL"
        out.append(Check("database_reachable", "FAIL", f"{var} is not set"))
    else:
        engine = engine_factory(url.get_secret_value())
        try:
            out += _database(engine, role)
        finally:
            engine.dispose()
    out += [_signing(s), _evidence(s), _ai(s), _egress(s, role)]
    if role == "api":
        out.append(_sign_in(s))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aisw.doctor")
    ap.add_argument("--role", choices=["api", "worker"], default="api")
    ap.add_argument("--env-file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        settings = load_settings(args.env_file)
    except (ValidationError, ValueError) as exc:
        print(f"FAIL  settings: {exc}", file=sys.stderr)
        return 2
    checks = run_checks(settings, args.role)
    if args.json:
        print(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            print(f"{c.status:4}  {c.name}: {c.detail}")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
