# Local development and tests

Needs `uv`, Node >= 24, npm and Google Chrome (system browser, nothing is downloaded). No Docker, no credentials.

```bash
cd backend && uv sync && uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest -q
cd web && npm install && npm run typecheck && npm run lint && npm test && npm run build && npm run e2e
python3 tools/secret_scan.py .
cd backend && uv run python ../tools/export_schemas.py --check && uv run python ../tools/sbom.py --check
```

Tests start an embedded PostgreSQL (pgserver). It leaks if a run is killed; macOS allows few shared-memory segments, so after a killed run:

```bash
tools/stop_stale_test_postgres.sh
```

It only matches this repository's own embedded servers. If `initdb` still fails, list leftovers with `ps aux | grep pgserver` before killing anything yourself.

Rules that keep tests honest: tests never contact a non-loopback host (a socket guard fails the test if code tries); no model weights exist (a scripted stub is used); fixture evidence is byte-identical between runs, so tests that reason about shared blobs use the isolated-database fixture.
