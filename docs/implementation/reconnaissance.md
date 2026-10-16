# Reconnaissance (M0)

Date: 2026-10-15. Repository: `aisw/` (new, `git init` on branch `main`, no prior commits).

## Actual state
- Greenfield: no pre-existing AISW code, UI, database, auth, CI or deployment manifests. Nothing to preserve or reuse.
- Parent workspace (`Claude Projects/`) holds unrelated projects; they are out of scope and untouched.
- Blueprint sources: `Agentic_Infrastructure_Security_Warden_Proof_Blueprint_v2_1_Open_Source.docx` and `AISW_v2_1_Open_Source_Public_URL_Test_Profile.md` (kept in the user's Downloads, not copied into the repo).

## Local toolchain (measured)
| Tool | State |
|---|---|
| Python | system 3.9.6 (unsuitable); uv 0.12.13 provides CPython 3.12.14 (used, pinned via `.python-version`) |
| Node / npm | 24.19.0 / 11.17.0 (pnpm absent; npm used) |
| git | 2.54.0 |
| docker, psql, opa, nmap | **not installed** |

Consequences: the dev loop must not require Docker. PostgreSQL-dependent tests (RLS, durable worker) need an embedded Postgres test harness, to be added in M1. Compose files will be authored in M3+/M8 and marked *unverified* until run. OPA and Nmap are not installed; the policy evaluator ships with a Python implementation behind an interface (ADR-003) and the Nmap adapter is built against golden fixtures only (live use requires an explicit go-ahead).

## Commands run and results (M0 baseline)
| Command | Result |
|---|---|
| `uv sync` (backend) | OK |
| `uv run ruff check .` / `ruff format --check .` | pass |
| `uv run mypy` (strict) | no issues, 22 files |
| `uv run pytest -q` | 13 passed (1 third-party deprecation warning from Starlette TestClient/httpx) |
| `npm run lint` (oxlint), `npm run typecheck`, `npm test` (vitest), `npm run build` | all pass; 1 test |
| `npm audit --omit=dev` | 0 vulnerabilities |

## Reusable components
None existing. New M0 assets: typed fail-closed `Settings`, FastAPI app factory (`/healthz`, `/readyz`), status vocabulary module in the UI, test layout matching blueprint section 14 layers.

## Gaps and risks
- No Postgres/OPA/Docker locally (see above) — mitigated by interfaces + embedded Postgres in M1.
- Blueprint inconsistencies G1–G14 are catalogued in `development-plan.md`; defaults accepted by the user.
- npm reported blocked install scripts (`allow-scripts` warning); none required for build/test so far.
- Licence questions (Nmap NPSL, AGPL components, feeds, model weights) remain open for the SBOM/licence gate.

## Assumptions
- Single-developer PoC; customer systems are never contacted before M9 and then only with explicit authorisation.
- Dev identity stub is acceptable until a Keycloak instance exists (ADR-006).

## File-level plan for M1
`backend/aisw/contracts/*` (envelope 1.1, manifest, permit, decision, domain entities), `backend/aisw/core/{tenant,rbac,audit,idempotency,redaction}.py`, `backend/migrations/` (Alembic), `backend/tests/{contract,security}/` negative suites, `tools/export_schemas.py`.

## M1 update
Embedded Postgres 16.2 via `pgserver` (dev dependency) resolved the missing-Postgres constraint for tests. Known quirk: pgserver's own `psql` helper breaks on paths containing spaces (this workspace path has one); we use psycopg/SQLAlchemy only. pgserver's licence (and bundled PostgreSQL) goes through the SBOM/licence gate in M8.

## M2 update
Added `cryptography` (Ed25519). `pip-audit`: no known vulnerabilities (run locally 2026-10-15). Probe finding recorded in ADR-013: Python `ipaddress.is_global` misclassifies multicast and NAT64-wrapped addresses, so `net_guard` does not rely on it alone.

## M3 update
Process findings worth remembering: (1) a mutation check showed a slow worker could double-write after losing its lease, fixed by fencing (ADR-014); (2) a silent no-op string replacement during editing was caught only because a test asserted the behaviour, a reminder to keep behavioural tests for every control; (3) the shared task queue made tests order-dependent until each test started from a drained queue.

## M4 update
Playwright runs on the system Google Chrome (`channel: chrome`), so no browser was downloaded. Lessons recorded: (1) React StrictMode runs effects twice on mount, so "skip the first run" focus logic must compare state (previous path) instead of a flag; (2) a disabled button makes Playwright wait until the test timeout, so never `.catch` a click; (3) axe cannot run inside a script-less sandboxed iframe, so such content is scanned as its own document; (4) the report HTML gained a `<main>` landmark because the accessibility scan exposed its absence; (5) an open fetch stream does not notice offline emulation, so the client listens for browser offline/online events.

## M5 update
Lessons: (1) test PKI certificates must have distinct subjects: two anchors with the same subject made OpenSSL report "self-signed" instead of "expired"; (2) a loopback-only socket guard (not just mocked DNS) is what makes "no public host contacted" a checked property; (3) a mutation that does not change behaviour proves nothing (one of mine was a no-op), so re-do it properly; (4) one unreproduced e2e timeout (double-click launch) appeared once under load and passed on 4 further runs; its wait was widened and the observation recorded here, cause not established.

## M6 update
Added `defusedxml` (+ `types-defusedxml`). Defects found by the new tests, all fixed: (1) the worker promoted a host to HIGH confidence because a second scanner "matched" the first scanner's provisional asset; (2) a value-taking Nmap flag with no value was accepted; (3) an OpenSCAP TestResult with zero evaluated rules would have become "no failures"; (4) with several adapters on one target only the first coverage ledger was kept (ledgers are now per target and adapter). Test hygiene: assertions about "not stored" must target evidence artifacts, because raw uploads legitimately keep the operator's file.

Operational finding (M6): ~28 embedded Postgres servers had leaked from killed e2e runs (Playwright stopped the server hard and uvicorn re-raises SIGTERM to the original handler, skipping cleanup), exhausting the machine's 32 shared-memory segments and failing 213 tests at setup with no code change. Fixed: SIGTERM handler + `finally` cleanup in `backend/e2e/server.py`, `exec` + `gracefulShutdown` in the Playwright config, and `tools/stop_stale_test_postgres.sh` (matches only this repo's venv). Verified: 0 processes left after an e2e run.

## M7 update
No new dependency (the model client uses the standard library only; no weights, no runtime installed). Lessons recorded: (1) three mutations survived the first test pass and exposed weak tests: no case on a rubric threshold boundary, an HTTP-redirect test that proved nothing because Python's `urllib` already refuses to redirect a 307 POST (a 302 was needed), and an "unassured recommendation" test that only hit the visibility check, not the 409 branch; all three were fixed and re-run (23 of 23 mutations caught); (2) finding and recommendation ids are deterministic across runs, so SQL assertions in shared-database tests must filter by `run_id`; (3) the first pipeline test run showed four older assurance tests counted new `risk:/scenario:/recommendation:` rows, now scoped to `finding:%`; (4) `npm test` also collected the Playwright specs under vitest, so the script is now `vitest run src`; (5) AI-disabled and AI-outage runs produce the same deterministic report shape (asserted), which is the property that matters if a model is ever unreliable.


## M8 update
No new dependency. Findings: (1) a test showed the report-export **denial was not audited** because the audit row shared the transaction the 403 rolled back (now recorded on its own connection); (2) the licence gate's first run found three components without recorded acceptance (certifi, colorama, tzdata) and revealed that `tzdata` is only a Windows dependency of psycopg, so Windows-only dependency edges are excluded from the runtime closure; (3) `evidence_artifacts` is append-only by trigger, so "purged" is derived from the retention log rather than a mutable column; (4) fixture evidence is byte-identical between runs, so retention tests need an isolated database (otherwise another test's unfinished run legitimately protects a shared blob); (5) a mutation of the export-denial audit survived until the test also checked the audit *result*; 15 of 15 M8 mutations are now caught. Permit renewal is deliberately not offered after a permit lapses or is revoked.
