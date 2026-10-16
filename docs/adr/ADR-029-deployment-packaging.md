# ADR-029: Deployment packaging: four processes, secret files, a doctor, and no root

**Status:** Accepted. The processes are proven live against Postgres. The container images and systemd units are written and statically tested, but have **never been built or loaded** (no Docker, Podman or systemd on the development machine).

## Context
`deploy/` did not exist, and `python -m aisw.orchestrator` had never run as a live process (pending-plan P0-4). Production also needs a way to apply migrations and enable the service roles without the API holding owner rights, and a way to tell a misconfigured host from a broken build.

## Decision
- **Four processes, one image.**
  - `aisw.bootstrap` is a one-shot step that runs as the schema owner. It applies migrations, then runs `ALTER ROLE aisw_app/aisw_worker LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD ...` with passwords read from 0600 files, built with `psycopg.sql`.
  - `aisw.api` runs uvicorn with `proxy_headers` honoured only from `AISW_API_TRUSTED_PROXIES`, no server header, and a 10-second graceful drain. It binds loopback by default.
  - `aisw.orchestrator` uses SIGTERM/SIGINT to stop after the current task and dispose of the engine. It touches a heartbeat file every loop; `--check-heartbeat` is its health probe and `--exit-when-idle` is for batch use.
  - The web tier is nginx serving the built UI and proxying `/api/` with buffering off (SSE). It sets the security headers and a CSP without `unsafe-inline`.
- **Secrets are files, never environment variables.** `load_settings()` reads a secrets directory, `AISW_SECRETS_DIR` or systemd's `$CREDENTIALS_DIRECTORY`, where each file is named after its setting. Compose mounts `./secrets/*`; systemd uses `LoadCredential=`. Env files hold only non-secret settings. A test fails if a compose or systemd environment entry looks like a secret, or if an env example names a setting that does not exist (unknown `AISW_*` variables are ignored at runtime).
- **Migration DSN.** Alembic prefers `AISW_MIGRATION_DATABASE_URL`, so the runtime DSN never needs owner rights. Migration 0012 grants `aisw_app` read access to `alembic_version` so the doctor can compare it with the head.
- **Doctor.** `python -m aisw.doctor --role api|worker [--json]` checks:
  - settings parse;
  - the environment;
  - the database is reachable;
  - the role is a service role, not a superuser, without BYPASSRLS;
  - RLS is forced on every tenant table;
  - migrations are at head;
  - signing custody (local file is a WARN);
  - the evidence store is a 0700 directory;
  - AI gating;
  - egress zones;
  - pending sign-offs (WARN while any is unapproved);
  - sign-in, for the API.

  Any FAIL exits 1. The systemd units run it in `ExecStartPre`.
- **Readiness.** `/readyz` runs `SELECT 1` and returns 503 until it succeeds; `/healthz` stays a liveness probe.
- **No root anywhere.**
  - Backend image: uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, pinned base images, `uv sync --frozen`.
  - Web: the unprivileged nginx image as uid 101.
  - Postgres: on an internal network with no published port.
  - Only the web port is published, on loopback, with TLS in front.
  - systemd: `ProtectSystem=strict`, an empty capability set, the `@system-service` syscall filter, `UMask=0077`, and evidence as the only writable path.

## Consequences
- Operators run bootstrap on every upgrade. It is idempotent and also rotates the database passwords.
- The image installs the project editable, so `migrations/` resolves next to the package. A test enforces this.
- uvicorn re-raises SIGTERM after a graceful shutdown, so the API's exit status is "killed by SIGTERM". systemd and Docker treat this as a clean stop.
- **Not verified:**
  - building the images;
  - `docker compose up`;
  - loading the systemd units;
  - Compose's handling of secret-file ownership (the README gives the uid chown step).

  These are the first install on a real host, recorded in P0-4 and owned by the platform admin.

## Tests
- `tests/integration/test_live_processes.py`:
  1. bootstrap through the CLI on a fresh database (twice, to show it is idempotent; no password in the output);
  2. start the API process and wait for `/readyz`;
  3. doctor for both roles (PASS on role, RLS, head, evidence; WARN on local signing and SSO);
  4. start the worker process;
  5. project, inventory, manifest, preflight, approval by a second person, launch, and **REPORT_READY** with reports readable by a third user;
  6. heartbeat probe;
  7. SIGTERM: worker exits 0, API logs "Application shutdown complete";
  8. bootstrap refuses world-readable and short password files.
- `tests/unit/test_deploy_packaging.py`:
  - images pinned and non-root, no `ADD <url>`;
  - compose hardening and network isolation;
  - secret names map to settings;
  - systemd sandbox keys, with `ExecStart` modules that exist;
  - nginx headers;
  - `.dockerignore` excludes secrets;
  - env examples name real settings;
  - `/readyz` returns 503 without a database;
  - heartbeat freshness.
- `tests/integration/test_migrations.py`: 0012 grants on upgrade and revokes on downgrade.
