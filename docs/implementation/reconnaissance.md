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
