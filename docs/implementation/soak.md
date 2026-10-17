# Multi-node worker soak results

Produced by `tests/integration/test_worker_soak.py` (ADR-044): worker processes on one machine share one PostgreSQL queue; every few seconds one worker gets SIGKILL and a fresh one starts. Fixture tasks are held for `AISW_SOAK_TASK_MS` so kills land mid-task. The default size runs in every `pytest`; larger rows were run by hand with `AISW_SOAK_RUNS`, `AISW_SOAK_WORKERS`, `AISW_SOAK_KILL_SECONDS` and `AISW_SOAK_REPORT=../docs/implementation/soak.md`.

Every row passed the same checks: every run ended (REPORT_READY, or failed only with `LEASE_EXPIRED_MAX_ATTEMPTS` after its task was killed on all three attempts); no task left RUNNING or over its attempt limit; evidence stored exactly once per finished task; gap-free, duplicate-free event logs; one report per finished run; audit chain verified; no traceback in surviving workers.

These are one developer laptop (Apple silicon, embedded PostgreSQL 16), not sizing for a deployment. Separate hosts, network partitions between workers and the database, and load from real adapters have not been tested; DoS sizing needs the target hardware.

| Date | Runs | Tasks | Workers | Kills | Lease | Tasks reclaimed | Reports ready | Wall time | Runs/min | Run p50 | Run p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-10-17 | 24 | 24 | 4 | 14 | 5s | 4 | 23/24 | 36s | 39.5 | 20.8s | 22.2s |
| 2026-10-17 | 120 | 120 | 6 | 28 | 5s | 9 | 120/120 | 128s | 56.3 | 92.9s | 116.3s |
| 2026-10-17 | 120 | 120 | 6 | 22 | 5s | 6 | 120/120 | 142s | 50.6 | 103.6s | 127.7s |
| 2026-10-17 | 120 | 120 | 6 | 24 | 5s | 7 | 120/120 | 127s | 56.5 | 92.1s | 113.9s |
