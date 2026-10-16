"""The CI workflow keeps its supply-chain and least-privilege properties and runs every local gate
(ADR-030). actionlint and zizmor check it too; this guards the properties they do not."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


def workflow() -> dict[Any, Any]:
    doc: dict[Any, Any] = yaml.safe_load(WORKFLOW.read_text())
    return doc


def steps(job: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = workflow()["jobs"][job]["steps"]
    return out


def runs(job: str) -> str:
    return "\n".join(s.get("run", "") for s in steps(job))


def test_actions_are_pinned_to_commit_shas() -> None:
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_least_privilege_and_bounded_jobs() -> None:
    doc = workflow()
    assert doc["permissions"] == {"contents": "read"}
    triggers = doc["on"] if "on" in doc else doc[True]  # PyYAML reads a bare `on` key as True
    assert set(triggers) == {"push", "pull_request"}
    assert "${{ secrets." not in WORKFLOW.read_text()
    for name, job in doc["jobs"].items():
        assert "permissions" not in job, name
        assert 0 < job["timeout-minutes"] <= 30, name
        checkout = next(
            s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
        )
        assert checkout["with"]["persist-credentials"] is False, name


def test_every_local_gate_runs_in_ci() -> None:
    backend = runs("backend")
    for gate in ("uv sync --frozen", "ruff check .", "ruff format --check .", "mypy aisw tests",
                 "pytest -q", "pip-audit", "export_schemas.py --check", "sbom.py --check",
                 "key_rotation_drill.py --emulator --rotate", "signoffs.py --check"):  # fmt: skip
        assert gate in backend, gate
    web = runs("web")
    for gate in ("npm ci", "npm run lint", "npm run check:types", "npm run typecheck", "npm test",
                 "npm run build"):  # fmt: skip
        assert gate in web, gate
    assert "npx playwright test" in runs("e2e")
    assert "secret_scan.py" in runs("hygiene") and "actionlint" in runs("hygiene")
    deploy = runs("deploy")
    for dockerfile in (REPO / "deploy" / "docker").glob("*.Dockerfile"):
        assert f"deploy/docker/{dockerfile.name}" in deploy, dockerfile.name
    assert "docker compose config" in deploy


def test_toolchain_matches_the_images() -> None:
    env = workflow()["env"]
    backend_image = (REPO / "deploy" / "docker" / "backend.Dockerfile").read_text()
    web_image = (REPO / "deploy" / "docker" / "web.Dockerfile").read_text()
    assert f"ghcr.io/astral-sh/uv:{env['UV_VERSION']} " in backend_image
    assert re.search(rf"FROM node:{env['NODE_VERSION']}\.", web_image)
