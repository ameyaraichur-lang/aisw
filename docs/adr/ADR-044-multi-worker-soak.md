# ADR-044: Multi-node worker soak with random kills

**Status:** Accepted (single machine; separate hosts not tested)

## Context
Lease, fencing and attempt limits (ADR-002) were tested with two in-process workers taking turns and with simulated crashes, never with independent worker processes being killed while they hold work.

## Decision
1. **Soak test** `tests/integration/test_worker_soak.py`: an isolated database, bootstrap, the API and N worker processes, each its own OS process and connection pool. Runs are launched over HTTP. Every `AISW_SOAK_KILL_SECONDS` one random worker gets SIGKILL (no cleanup, no lease release) and a fresh worker starts.
2. **Checks that must hold however the kills land:**
   - every run ends: REPORT_READY, or failed only with `LEASE_EXPIRED_MAX_ATTEMPTS` (its task was killed on every attempt);
   - no task is left RUNNING or over its attempt limit;
   - evidence is stored exactly once per finished task;
   - each run's event log is gap-free and duplicate-free; one report per finished run;
   - the tenant's audit chain verifies; surviving workers log no traceback;
   - at least one task was reclaimed after a kill, so a pass proves the crash path ran.
3. **Two settings make it possible:** `AISW_WORKER_LEASE_SECONDS` (default 300, minimum 5) sets how soon a dead worker's task is reclaimed; `AISW_FIXTURE_DELAY_MS` (dev/test only, refused in prod) holds fixture tasks so kills land mid-task.
4. **Default size runs in every `pytest`** (4 workers, 24 runs, a kill every 1.5 s, about 100 s). Larger runs are by hand; results go to `docs/implementation/soak.md`.

## Consequences
- The lease must exceed the slowest adapter call; a task that outlives its lease is re-run elsewhere and the first worker's result is discarded by fencing.
- A task killed on all three attempts fails its run. That outcome is explained, not silent, but a real deployment with frequent worker loss would see it; operators should treat repeated `LEASE_EXPIRED_MAX_ATTEMPTS` as a host problem.
- Not tested: workers on separate hosts, network partitions between a worker and the database, clock skew between hosts, and load from real adapters. DoS sizing needs the target hardware.
