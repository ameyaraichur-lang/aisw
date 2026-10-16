# Deploying AISW

Two supported layouts, both described in ADR-029:

- **Compose, one host:** `deploy/compose/`, with images from `deploy/docker/`.
- **Native, systemd:** `deploy/systemd/`, with a Python virtualenv and an existing Postgres 16.

Either way, there are four processes:

| Process | Command | Database role | Network |
|---|---|---|---|
| bootstrap (one-shot) | `python -m aisw.bootstrap` | schema owner | database only |
| API | `python -m aisw.api` | `aisw_app` | database, IdP, KMS; behind the web proxy |
| worker | `python -m aisw.orchestrator` | `aisw_worker` | database, KMS, model endpoint, scan zones |
| web | nginx serving `web/dist`, proxying `/api/` | none | API only |
| opa (optional) | `opa run --server` on the packaged Rego (ADR-031) | none | none; reached by API and worker |

`python -m aisw.doctor --role api|worker` checks a host before start-up. It exits 1 if any check FAILs.

> **Verification status.** The processes are proven live: bootstrap, API, worker, doctor, heartbeat and SIGTERM shutdown all run as real OS processes against Postgres, and a run is driven to REPORT_READY over HTTP (`backend/tests/integration/test_live_processes.py`). The **container images have never been built** and the **systemd units have never been loaded**, because the development machine has no Docker, Podman or systemd. Their contents are checked statically by `backend/tests/unit/test_deploy_packaging.py`. The first real install is pending-plan P0-4, owned by the platform admin.

## Secrets

Secrets are never put in environment variables or env files. Each one is a file whose name matches a setting (`aisw_database_url` is read as `AISW_DATABASE_URL`), in a directory named by `AISW_SECRETS_DIR`. Under systemd, that directory is `$CREDENTIALS_DIRECTORY`, which is picked up automatically.

| File | Used by | Content |
|---|---|---|
| `aisw_migration_database_url` | bootstrap | the schema owner's DSN (`AISW_MIGRATION_DATABASE_URL_FILE`) |
| `pg_app_password`, `pg_worker_password` | bootstrap | login passwords it sets for `aisw_app` and `aisw_worker` (0600, at least 16 characters) |
| `aisw_database_url` | API | the `postgresql+psycopg` DSN for the `aisw_app` role and its password |
| `aisw_worker_database_url` | worker | the `postgresql+psycopg` DSN for the `aisw_worker` role and its password |
| `aisw_session_secret` | API | at least 32 random characters (cookie signing, ADR-026) |
| `aisw_oidc_client_secret` | API | from the IdP client registration |
| `kms_app_token` | API, worker | Transit token allowed only to read and sign (ADR-027); named by `AISW_KMS_TOKEN_FILE` |

Rotate a database password by writing the new file and re-running bootstrap; it is idempotent. Then restart the API and worker.

## Compose (one host)

```sh
cd deploy/compose
cp aisw.env.example aisw.env      # non-secret settings: IdP, KMS, egress zones
./make-secrets.sh                 # random DB passwords and session secret into ./secrets (0600)
# write secrets/aisw_oidc_client_secret and secrets/kms_app_token from your IdP and KMS
docker compose up -d --build
docker compose run --rm api aisw.doctor --role api
docker compose run --rm worker aisw.doctor --role worker
```

Compose bind-mounts secret files with the host's ownership and mode. On Linux, give the backend files to uid 10001 and the Postgres file to uid 999 so the non-root containers can read them:

```sh
sudo chown 10001:10001 secrets/aisw_* secrets/pg_app_password secrets/pg_worker_password secrets/kms_app_token
sudo chown 999:999 secrets/pg_owner_password
```

Only the web service is published, and only on `127.0.0.1:8080`. Terminate TLS in front of it with your load balancer or reverse proxy. The `data` and `app` networks are internal. Only the API and worker are on `egress`; filter that at the host with the rules from `tools/egress_check.py render` (ADR-028).

## Native (systemd)

1. Create the service user: `useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin aisw`.
2. Install the code at `/opt/aisw`, then run `cd /opt/aisw/backend && uv sync --frozen --no-dev`.
3. Build the UI with `cd web && npm ci && npm run build`. Serve `web/dist` with nginx using `deploy/docker/nginx.conf`, changing `proxy_pass` to `http://127.0.0.1:8000`.
4. Postgres 16: create the `aisw` database and a schema-owner role. Migration 0001 creates `aisw_app` and `aisw_worker`; bootstrap enables their login.
5. Copy `deploy/systemd/aisw.env.example` to `/etc/aisw/aisw.env` and put the secret files in `/etc/aisw/secrets/` (root:root 0600). systemd hands them to the service as credentials.
6. Create `/var/lib/aisw/evidence`, owned by `aisw` with mode 0700.
7. For the OPA engine, install the pinned binary and check its checksum: `curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.21.2/opa_linux_amd64_static`, then `echo "830ab11f61ffec760b5e19db0d7ad02bf037e13f5ef4d665faeaf17632177527  opa_linux_amd64_static" | sha256sum -c`. Install it as `/usr/local/bin/opa` (0755) and enable `aisw-opa`. The API and worker refuse to start if OPA serves different policy from the build.
8. `systemctl enable --now aisw-bootstrap aisw-opa aisw-api aisw-worker aisw-retention.timer`.

Each long-running unit runs the doctor in `ExecStartPre`, so a misconfigured host refuses to start and the reason is in `journalctl -u aisw-api`. The units are sandboxed: `ProtectSystem=strict`, no capabilities, `@system-service` syscalls, and evidence is the only writable path.

## Retention checks

`aisw-retention.timer` runs `python -m aisw.evidence.retention_schedule` daily for each tenant in `AISW_RETENTION_TENANTS`. Every check records the dry-run plan (`retention_checks`, shown on the Retention page) and an audit entry. Evidence moves to quarantine only when `AISW_RETENTION_AUTO_EXECUTE=true` **and** an earlier check saw the identical plan hash at least `AISW_RETENTION_CONFIRM_HOURS` before; any change (a new hold, a new run, a release) starts a new window. Leave auto-execute off until the retention owner has approved it; a retention manager can always execute a reviewed plan from the Retention page. With Compose, run it from the host's scheduler: `docker compose run --rm api aisw.evidence.retention_schedule`. Final deletion from quarantine stays manual.

## Health

- `GET /healthz` returns 200 while the process is up (liveness).
- `GET /readyz` returns 200 only when the database answers. It also reports whether a signer and SSO are configured, and returns 503 otherwise (readiness).
- Worker: `python -m aisw.orchestrator --check-heartbeat` exits 0 when the loop has touched `AISW_WORKER_HEARTBEAT_FILE` within the last 30 seconds.
- On SIGTERM, the worker finishes its current task and exits 0. The API drains connections for up to 10 seconds. uvicorn then re-raises SIGTERM, which systemd and Docker treat as a clean stop.

## Upgrades

Stop the worker, run bootstrap (migrations apply forward only to head), then start the API and worker. Every migration is independently reversible (`backend/tests/integration/test_migrations.py`), but take a database backup before any upgrade.
