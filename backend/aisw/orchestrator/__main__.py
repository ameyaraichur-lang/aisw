"""Worker process entry point: ``python -m aisw.orchestrator`` (deploy/, ADR-029).

Connects as the dedicated ``aisw_worker`` database role (AISW_WORKER_DATABASE_URL). SIGTERM/SIGINT
finish the current step and exit 0. With AISW_WORKER_HEARTBEAT_FILE set, the file is touched every
loop so a supervisor can check liveness: ``python -m aisw.orchestrator --check-heartbeat``.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from types import FrameType

from aisw.api.container import build_container
from aisw.core.config import get_settings
from aisw.core.db import make_engine
from aisw.core.redaction import RedactingFilter

log = logging.getLogger("aisw.worker")
HEARTBEAT_MAX_AGE = 30.0


def heartbeat_fresh(
    path: Path, *, now: float | None = None, max_age: float = HEARTBEAT_MAX_AGE
) -> bool:
    try:
        age = (now if now is not None else time.time()) - path.stat().st_mtime
    except OSError:
        return False
    return age <= max_age


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aisw.orchestrator")
    ap.add_argument("--check-heartbeat", action="store_true", help="exit 0 if the worker is alive")
    ap.add_argument("--exit-when-idle", type=float, metavar="SECONDS",
                    help="exit 0 after this long with no work (batch/cron use)")  # fmt: skip
    ap.add_argument("--worker-id", default="worker-main")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
    settings = get_settings()
    beat = settings.worker_heartbeat_file
    if args.check_heartbeat:
        if beat is None:
            print("AISW_WORKER_HEARTBEAT_FILE is not set", file=sys.stderr)
            return 2
        return 0 if heartbeat_fresh(beat) else 1
    if settings.worker_database_url is None:
        raise SystemExit("AISW_WORKER_DATABASE_URL is required")
    engine = make_engine(settings.worker_database_url.get_secret_value())
    worker = build_container(settings, engine).make_worker(worker_id=args.worker_id)
    stop = threading.Event()

    def _stop(signum: int, _: FrameType | None) -> None:
        log.info("worker stopping on signal %s", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("worker started id=%s", args.worker_id)
    idle_since = time.monotonic()
    while not stop.is_set():
        if beat is not None:
            beat.touch()
        try:
            progressed = worker.step()
        except Exception:  # keep the loop alive; the lease/attempt machinery handles the task
            log.exception("worker step failed")
            progressed = False
        if progressed:
            idle_since = time.monotonic()
        elif (
            args.exit_when_idle is not None and time.monotonic() - idle_since >= args.exit_when_idle
        ):
            log.info("worker idle for %.0fs, exiting", args.exit_when_idle)
            break
        else:
            stop.wait(1.0)
    engine.dispose()
    log.info("worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
