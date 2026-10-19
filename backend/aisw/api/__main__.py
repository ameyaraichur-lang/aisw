"""API process entry point: ``python -m aisw.api`` (deploy/, ADR-029).

Connects as the ``aisw_app`` role (AISW_DATABASE_URL). Binds AISW_API_HOST:AISW_API_PORT
(loopback by default); X-Forwarded-* headers are honoured only from AISW_API_TRUSTED_PROXIES.
"""

from __future__ import annotations

import logging

import uvicorn

from aisw.api.app import create_app
from aisw.core.config import get_settings
from aisw.core.redaction import RedactingFilter


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
    settings = get_settings()
    if settings.database_url is None:
        raise SystemExit("AISW_DATABASE_URL is required")
    uvicorn.run(
        create_app(settings), host=settings.api_host, port=settings.api_port, proxy_headers=True,
        forwarded_allow_ips=settings.api_trusted_proxies, server_header=False, log_config=None,
        timeout_graceful_shutdown=10,
    )  # fmt: skip


if __name__ == "__main__":
    main()
