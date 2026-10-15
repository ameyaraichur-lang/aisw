"""Worker process entry point: ``python -m aisw.orchestrator``.

Connects as the dedicated ``aisw_worker`` database role (AISW_WORKER_DATABASE_URL). Status: written
but not exercised against a live deployment (see docs/implementation/status.md).
"""

from __future__ import annotations

import logging
import time

from aisw.api.container import build_container
from aisw.core.config import get_settings
from aisw.core.db import make_engine
from aisw.core.redaction import RedactingFilter

log = logging.getLogger("aisw.worker")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
    settings = get_settings()
    if settings.worker_database_url is None:
        raise SystemExit("AISW_WORKER_DATABASE_URL is required")
    engine = make_engine(settings.worker_database_url.get_secret_value())
    worker = build_container(settings, engine).make_worker(worker_id="worker-main")
    log.info("worker started")
    while True:
        try:
            progressed = worker.step()
        except Exception:  # keep the loop alive; the lease/attempt machinery handles the task
            log.exception("worker step failed")
            progressed = False
        if not progressed:
            time.sleep(1.0)


if __name__ == "__main__":
    main()
