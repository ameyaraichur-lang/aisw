#!/bin/sh
# Writes random secrets for a local compose deployment into ./secrets (0600). Production should
# take these from the organisation's secret manager instead. Never commit ./secrets.
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }
for f in pg_owner_password pg_app_password pg_worker_password aisw_session_secret; do
  [ -s "secrets/$f" ] || rand > "secrets/$f"
done
owner=$(cat secrets/pg_owner_password); app=$(cat secrets/pg_app_password); worker=$(cat secrets/pg_worker_password)
printf 'postgresql+psycopg://aisw_owner:%s@postgres:5432/aisw' "$owner" > secrets/aisw_migration_database_url
printf 'postgresql+psycopg://aisw_app:%s@postgres:5432/aisw' "$app" > secrets/aisw_database_url
printf 'postgresql+psycopg://aisw_worker:%s@postgres:5432/aisw' "$worker" > secrets/aisw_worker_database_url
for f in aisw_oidc_client_secret kms_app_token; do
  [ -s "secrets/$f" ] || { echo "write secrets/$f from your IdP / KMS (0600)" >&2; : > "secrets/$f"; }
done
echo "secrets written to $(pwd)/secrets"
