"""Database bootstrap: ``python -m aisw.bootstrap`` (deploy/, ADR-029).

Runs as the schema owner (AISW_MIGRATION_DATABASE_URL, or a 0600 file named by
AISW_MIGRATION_DATABASE_URL_FILE): applies migrations to head, then enables
login for the ``aisw_app`` and ``aisw_worker`` roles with passwords read from 0600 files written by
the secret provider. Neither role is a superuser or can bypass row-level security. Idempotent.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, text

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
ROLES = ("aisw_app", "aisw_worker")


class BootstrapError(Exception):
    pass


def read_password(path: Path) -> str:
    if not path.is_file():
        raise BootstrapError(f"password file {path.name} is missing")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise BootstrapError(f"password file {path.name} must not be group/world accessible")
    pw = path.read_text().strip()
    if len(pw) < 16 or any(c.isspace() for c in pw):
        raise BootstrapError(f"password in {path.name} must be at least 16 non-space characters")
    return pw


def bootstrap(owner_url: str, passwords: dict[str, str], *, migrations: Path = MIGRATIONS) -> str:
    engine = create_engine(owner_url)
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(migrations))
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
        with engine.begin() as conn:
            raw = conn.connection.dbapi_connection
            for role, pw in passwords.items():
                stmt = sql.SQL("ALTER ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(pw)
                )
                conn.exec_driver_sql(stmt.as_string(raw))  # type: ignore[arg-type]
            head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        return str(head)
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aisw.bootstrap")
    ap.add_argument("--app-password-file", type=Path)
    ap.add_argument("--worker-password-file", type=Path)
    ap.add_argument("--migrations", type=Path, default=MIGRATIONS)
    args = ap.parse_args(argv)
    url = os.environ.get("AISW_MIGRATION_DATABASE_URL")
    if not url and (file := os.environ.get("AISW_MIGRATION_DATABASE_URL_FILE")):
        try:
            url = read_password(Path(file))
        except BootstrapError as exc:
            print(f"bootstrap failed: {exc}", file=sys.stderr)
            return 2
    if not url:
        print("AISW_MIGRATION_DATABASE_URL (the schema owner's DSN) is required", file=sys.stderr)
        return 2
    try:
        passwords = {
            role: read_password(path)
            for role, path in zip(
                ROLES, (args.app_password_file, args.worker_password_file), strict=True
            )
            if path is not None
        }
        head = bootstrap(url, passwords, migrations=args.migrations)
    except BootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 2
    print(f"database at revision {head}; login enabled for {', '.join(passwords) or 'no roles'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
