# syntax=docker/dockerfile:1.7
# AISW backend image: API (python -m aisw.api), worker (python -m aisw.orchestrator),
# bootstrap (python -m aisw.bootstrap) and doctor (python -m aisw.doctor). Build from the repo root:
#   docker build -f deploy/docker/backend.Dockerfile -t aisw-backend:<version> .
FROM python:3.12.11-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/aisw ./aisw
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./
# Editable on purpose: bootstrap and doctor find migrations/ beside the aisw package in /app.
RUN uv sync --frozen --no-dev

FROM python:3.12.11-slim-bookworm
RUN groupadd --system --gid 10001 aisw \
 && useradd --system --uid 10001 --gid aisw --home-dir /nonexistent --shell /usr/sbin/nologin aisw \
 && install -d -o aisw -g aisw -m 0700 /var/lib/aisw /var/lib/aisw/evidence
WORKDIR /app
COPY --from=build --chown=root:root /app /app
ENV PATH=/app/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AISW_ENV=prod AISW_API_HOST=0.0.0.0 AISW_EVIDENCE_DIR=/var/lib/aisw/evidence \
    AISW_SECRETS_DIR=/run/secrets
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["python", "-m"]
CMD ["aisw.api"]
