"""Shared fixtures: a real embedded PostgreSQL 16 (pgserver) with migrations applied.

RLS and trigger behaviour is only meaningful on real Postgres, so SQLite is never used.
Passwords are generated per test session and never written anywhere.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pgserver
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import URL, Engine, create_engine, text

from aisw.api.app import create_app
from aisw.core.config import Settings

BACKEND = Path(__file__).resolve().parents[1]


def alembic_cfg(engine: Engine) -> tuple[Config, object]:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    return cfg, engine


def migrate(engine: Engine, target: str, *, down: bool = False) -> None:
    cfg, _ = alembic_cfg(engine)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        (command.downgrade if down else command.upgrade)(cfg, target)


def _socket_dir(uri: str) -> str:
    return parse_qs(urlparse(uri).query)["host"][0]


def _url(user: str, password: str | None, db: str, host: str) -> URL:
    return URL.create(
        "postgresql+psycopg", username=user, password=password, database=db, query={"host": host}
    )


@pytest.fixture(scope="session")
def pg_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    server = pgserver.get_server(tmp_path_factory.mktemp("pg") / "data", cleanup_mode="stop")  # type: ignore[attr-defined]
    yield server
    server.cleanup()


def make_db(server: Any, name: str) -> Engine:
    host = _socket_dir(server.get_uri())
    admin = create_engine(_url("postgres", None, "postgres", host), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    admin.dispose()
    return create_engine(_url("postgres", None, name, host))


@pytest.fixture(scope="session")
def owner_engine(pg_server: Any) -> Engine:
    eng = make_db(pg_server, "aisw_test")
    migrate(eng, "head")
    return eng


@pytest.fixture(scope="session")
def app_engine(pg_server: Any, owner_engine: Engine) -> Iterator[Engine]:
    """Connects as aisw_app: not owner, not superuser, no BYPASSRLS."""
    pw = secrets.token_hex(16)
    with owner_engine.begin() as c:
        c.execute(text(f"ALTER ROLE aisw_app LOGIN PASSWORD '{pw}'"))
    eng = create_engine(
        _url("aisw_app", pw, "aisw_test", _socket_dir(pg_server.get_uri())), future=True
    )
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def worker_engine(pg_server: Any, owner_engine: Engine, app_engine: Engine) -> Iterator[Engine]:
    """Connects as aisw_worker: inherits app grants, plus cross-tenant discovery of open work."""
    pw = secrets.token_hex(16)
    with owner_engine.begin() as c:
        c.execute(text(f"ALTER ROLE aisw_worker LOGIN PASSWORD '{pw}'"))
    eng = create_engine(
        _url("aisw_worker", pw, "aisw_test", _socket_dir(pg_server.get_uri())), future=True
    )
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def opa_url() -> Iterator[str]:
    from tests.opa_server import opa_server

    with opa_server() as url:
        yield url


@pytest.fixture()
def client(app_engine: Engine) -> TestClient:
    settings = Settings(env="test", dev_auth_stub=True)
    return TestClient(create_app(settings, engine=app_engine))


@pytest.fixture()
def uid() -> str:
    return uuid.uuid4().hex[:12]


def auth(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer dev-{user}"}


@pytest.fixture()
def env(app_engine: Engine) -> Any:
    from tests.support import make_env

    return make_env(app_engine)


@pytest.fixture()
def sl(app_engine: Engine, worker_engine: Engine, tmp_path: Any) -> Any:
    from tests.slice import Slice

    return Slice(app_engine, worker_engine, tmp_path / "evidence")


@pytest.fixture()
def sl_iso(
    pg_server: Any, app_engine: Engine, worker_engine: Engine, tmp_path: Any
) -> Iterator[Any]:
    """A slice on its OWN freshly migrated database.

    Fixture evidence is byte-identical between runs, so tests that reason about which blobs are
    shared (retention) must not see other tests' runs. Same cluster, same roles and passwords.
    """
    from tests.slice import Slice

    name = f"iso_{uuid.uuid4().hex[:10]}"
    owner = make_db(pg_server, name)
    migrate(owner, "head")
    app = create_engine(app_engine.url.set(database=name), future=True)
    worker = create_engine(worker_engine.url.set(database=name), future=True)
    try:
        yield Slice(app, worker, tmp_path / "evidence")
    finally:
        for e in (app, worker, owner):
            e.dispose()
