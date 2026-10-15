"""Alembic environment: migrations run as the schema owner, never as the app role."""

import os

from alembic import context
from sqlalchemy import create_engine

config = context.config


def run() -> None:
    conn = config.attributes.get("connection")
    if conn is not None:
        context.configure(connection=conn, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()
        return
    url = os.environ.get("AISW_DATABASE_URL")
    if not url:
        raise RuntimeError("AISW_DATABASE_URL must be set to run migrations")
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


run()
