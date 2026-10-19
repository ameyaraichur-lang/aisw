# Operating the worker and the task queue

Start: `cd backend && AISW_WORKER_DATABASE_URL=<dsn for role aisw_worker> uv run python -m aisw.orchestrator` **(unverified live)**. The DSN comes from your secret provider; never paste it into a ticket or log.

How it behaves (all tested, including worker processes killed at random: `docs/implementation/soak.md`): tasks are claimed with a lease (`AISW_WORKER_LEASE_SECONDS`, default 300; keep it above the slowest adapter call) and a fencing token; a crashed worker's task becomes claimable when the lease expires; each task has at most 3 attempts; retries use exponential backoff (2 s base, doubling) with jitter; a worker that lost its lease cannot write. A run only advances when all its tasks are terminal.

| Symptom | Check | Action |
|---|---|---|
| Run stays in `ASSESSMENT_DISPATCH` | `GET /api/v1/assessments/{run}/tasks`: QUEUED with a future `available_at` = backing off; RUNNING with an old lease = crashed worker | Backing off: wait. Crashed: the next worker claims it after the lease; do not edit rows |
| Task `REJECTED` with `PERMIT_*` | Event `task.failed` error codes | See [permits-and-keys](permits-and-keys.md). A lapsed or revoked permit needs a **new launch** |
| Task `FAILED` with `RETRIES_EXHAUSTED` | Adapter error code in the event | Fix the source, launch a new run. Old evidence is kept |
| Want to stop a run | `POST /api/v1/assessments/{run}/cancel` (operator) | Queued tasks are cancelled; a running task finishes and its evidence is kept; no report is produced |
| Many runs failing together | Count `task.failed` by code | Retries are bounded and spaced; a storm cannot hot-loop. Look for a shared cause (adapter, source) |

Never `UPDATE` queue tables by hand: the lease/fencing machinery assumes it is the only writer.
