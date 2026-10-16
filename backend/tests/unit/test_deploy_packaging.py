"""Static checks on deploy/: images run non-root and pinned, compose is hardened with no inline
secrets, systemd units are sandboxed, nginx sets security headers, build contexts exclude secrets.

Docker, Compose and systemd are not available on the development machine, so these files have
never been built or started (ADR-029); these tests keep them honest until a real run.
"""

from __future__ import annotations

import configparser
import importlib.util
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from aisw.api.app import create_app
from aisw.core.config import Settings
from aisw.orchestrator.__main__ import heartbeat_fresh

DEPLOY = Path(__file__).resolve().parents[3] / "deploy"
REPO = DEPLOY.parent
SECRETISH = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|DATABASE_URL)$")


def compose() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load((DEPLOY / "compose" / "compose.yaml").read_text())
    return doc


PROCESS_ONLY = {
    "AISW_MIGRATION_DATABASE_URL",
    "AISW_MIGRATION_DATABASE_URL_FILE",
    "AISW_SECRETS_DIR",
}


@pytest.mark.parametrize(
    "path",
    ["deploy/compose/aisw.env.example", "deploy/systemd/aisw.env.example",
     "deploy/egress/example.env", ".env.example"],
)  # fmt: skip
def test_env_examples_name_real_settings(path: str) -> None:
    """Unknown AISW_* variables are ignored at runtime, so a typo here would silently not apply."""
    known = {f"AISW_{n.upper()}" for n in Settings.model_fields} | PROCESS_ONLY
    names = set(re.findall(r"^#?\s*(AISW_[A-Z0-9_]+)=", (REPO / path).read_text(), re.M))
    assert names and not names - known, sorted(names - known)


def test_images_are_pinned_and_run_as_non_root() -> None:
    for name in ("backend.Dockerfile", "web.Dockerfile"):
        text = (DEPLOY / "docker" / name).read_text()
        bases = re.findall(r"^FROM\s+(\S+)", text, re.M)
        assert bases and all(":" in b and not b.endswith(":latest") for b in bases), bases
        assert re.findall(r"^USER\s+(\S+)", text, re.M)[-1] not in {"root", "0", "0:0"}
        assert not re.search(r"^ADD\s+https?://", text, re.M)
        assert "--frozen" in text or "npm ci" in text  # lockfile installs only


def test_backend_image_keeps_migrations_beside_the_package() -> None:
    text = (DEPLOY / "docker" / "backend.Dockerfile").read_text()
    assert "COPY backend/aisw ./aisw" in text and "COPY backend/migrations ./migrations" in text
    assert "--no-editable" not in text  # MIGRATIONS resolves relative to the aisw package


def test_compose_services_are_hardened_and_secret_free() -> None:
    doc = compose()
    services = doc["services"]
    assert set(services) == {"postgres", "bootstrap", "api", "worker", "web", "opa"}
    for name, svc in services.items():
        assert svc.get("read_only") is True, name
        assert svc.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        for key, value in (svc.get("environment") or {}).items():
            if SECRETISH.search(key):
                pytest.fail(
                    f"{name}: secret-looking variable {key}={value!r} must be a secret file"
                )
        if name != "bootstrap":
            assert "healthcheck" in svc, name
        if name not in {"postgres"}:
            assert str(svc.get("user", "")).split(":")[0] not in {"", "0", "root"}, name
    assert "ports" not in services["postgres"] and "ports" not in services["api"]
    assert services["web"]["ports"] == ["127.0.0.1:8080:8080"]
    for net in ("data", "app", "policy"):
        assert doc["networks"][net]["internal"] is True, net
    opa = services["opa"]
    assert opa["networks"] == ["policy"] and "ports" not in opa
    assert all(v.endswith(":ro") for v in opa["volumes"])
    assert opa["image"].startswith("openpolicyagent/opa:") and "latest" not in opa["image"]
    assert (
        "egress" not in services["postgres"]["networks"]
        and "egress" not in services["web"]["networks"]
    )
    assert (
        services["api"]["depends_on"]["bootstrap"]["condition"] == "service_completed_successfully"
    )
    for s in doc["secrets"].values():
        assert s["file"].startswith("./secrets/")
    assert "secrets/" in (DEPLOY / "compose" / ".gitignore").read_text()


def test_compose_secret_names_match_settings_fields() -> None:
    """Secret files mounted at /run/secrets are read by name (AISW_SECRETS_DIR)."""
    fields = {f"aisw_{n}" for n in Settings.model_fields}
    doc = compose()
    for svc in ("api", "worker"):
        for name in doc["services"][svc]["secrets"]:
            assert name in fields or name == "kms_app_token", name


@pytest.mark.parametrize(
    "unit",
    ["aisw-api.service", "aisw-worker.service", "aisw-bootstrap.service", "aisw-opa.service"],
)
def test_systemd_units_are_sandboxed(unit: str) -> None:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment,method-assign]
    cp.read_string((DEPLOY / "systemd" / unit).read_text())
    svc = cp["Service"]
    assert svc["User"] == "aisw" and svc["NoNewPrivileges"] == "yes"
    assert svc["ProtectSystem"] == "strict" and svc["CapabilityBoundingSet"] == ""
    assert svc["UMask"] == "0077" and "PrivateTmp" in svc
    if unit == "aisw-opa.service":
        assert "--addr 127.0.0.1:" in svc["ExecStart"] and "*_test.rego" in svc["ExecStart"]
        assert svc["IPAddressDeny"] == "any"
    else:
        module = re.search(r"python -m (\S+)", svc["ExecStart"])
        assert module and importlib.util.find_spec(module.group(1)) is not None
    text = (DEPLOY / "systemd" / unit).read_text()
    assert not re.search(r"Environment=AISW_\w*(PASSWORD|SECRET|DATABASE_URL)=", text)


def test_nginx_sets_security_headers_and_streams_sse() -> None:
    conf = (DEPLOY / "docker" / "nginx.conf").read_text()
    for header in ("Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy",
                   "X-Frame-Options", "Permissions-Policy"):  # fmt: skip
        assert header in conf
    assert "frame-ancestors 'none'" in conf and "'unsafe-inline'" not in conf
    assert "proxy_buffering off" in conf and "server_tokens off" in conf


def test_build_context_excludes_secrets() -> None:
    ignore = (REPO / ".dockerignore").read_text().splitlines()
    for pattern in (
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/*.key",
        "deploy/compose/secrets",
        "**/.venv",
    ):
        assert pattern in ignore, pattern


def test_readyz_reports_not_ready_without_a_database() -> None:
    r = TestClient(create_app(Settings(env="test"))).get("/readyz")
    assert r.status_code == 503 and r.json()["database_reachable"] is False


def test_heartbeat_freshness(tmp_path: Path) -> None:
    beat = tmp_path / "hb"
    assert not heartbeat_fresh(beat)
    beat.touch()
    assert heartbeat_fresh(beat)
    assert not heartbeat_fresh(beat, now=beat.stat().st_mtime + 31)
