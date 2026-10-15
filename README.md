# Agentic Infrastructure Security Warden (AISW)

Customer-hosted, **read-only**, evidence-first infrastructure security assessment platform (blueprint v2.1, open-source-only). Early build: see `docs/implementation/development-plan.md` for the plan and `docs/implementation/status.md` for what is implemented vs mocked vs planned.

## Local development (no credentials, no Docker needed)
Requirements: `uv` (provides Python 3.12), Node >= 24, npm.

```bash
cd backend && uv sync && uv run ruff check . && uv run mypy && uv run pytest -q
cd web && npm install && npm run lint && npm run typecheck && npm test && npm run build
python3 tools/secret_scan.py .
```

Run the API: `cd backend && AISW_ENV=dev uv run uvicorn --factory aisw.api.app:create_app`
Tests use an embedded PostgreSQL 16 (pgserver, dev dependency) so row-level-security behaviour is tested for real; no Docker needed.
Export JSON Schemas: `cd backend && uv run python ../tools/export_schemas.py` (CI fails on drift).
Run the worker: `cd backend && AISW_WORKER_DATABASE_URL=<dsn for role aisw_worker> uv run python -m aisw.orchestrator` (unverified live).
Run the UI: `cd web && npm run dev`

## Safety defaults
Configuration is fail-closed (`backend/aisw/core/config.py`): read-only mode, scope manifest required, active scans need approval, AI and ticket creation off, dev auth stub only in dev/test. Copy `.env.example` for names only — never commit real values.

## Layout
`docs/` plan, ADRs, recon · `backend/` FastAPI services and tests · `web/` React/TS console · `deploy/` deployment assets (later) · `tools/` repo tooling.
