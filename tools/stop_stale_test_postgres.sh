#!/bin/sh
# Stops ONLY the embedded PostgreSQL servers that this project's test tooling (pgserver) started and
# failed to stop (e.g. after a killed test run). macOS allows few shared-memory segments, so leaked
# servers eventually make `initdb` fail at test setup. It matches this repository's venv path only.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATTERN="$ROOT/backend/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/postgres"
PIDS=$(ps -axo pid,command | grep -F "$PATTERN" | grep -v grep | grep -- "-D " | awk '{print $1}')
[ -z "$PIDS" ] && { echo "no stale test postgres servers"; exit 0; }
echo "stopping: $PIDS"
kill -TERM $PIDS
