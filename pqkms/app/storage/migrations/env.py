# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Alembic environment.

Runs in two ways:
  * Programmatically on server startup — app/storage/migrate.py passes a live
    Connection via config.attributes["connection"], so migrations execute on the
    same engine (and SQLite pragmas) the app uses.
  * From the `alembic` CLI — no connection is supplied, so we build an engine
    from PQKMS_DB_URL (or the SQLite quickstart default), reusing the app's own
    engine factory so dialect/pragma behaviour is identical.

render_as_batch is enabled so ALTER operations work on SQLite (which cannot ALTER
columns in place): Alembic recreates the table transparently. It is a no-op on
PostgreSQL, which does real ALTERs.
"""
from __future__ import annotations

from alembic import context

# The migrations dir lives under the app package; importing app.* works because
# alembic.ini sets prepend_sys_path=. (the pqkms project root).
from app.storage.engine import make_engine
from app.storage.schema import metadata

config = context.config
target_metadata = metadata


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL to stdout (alembic upgrade --sql). Rarely used; supported for completeness."""
    from app.storage.engine import resolve_url

    context.configure(
        url=resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # A connection injected by the startup runner takes precedence so migrations
    # run on the app's own engine/transaction.
    connection = config.attributes.get("connection", None)
    if connection is not None:
        _run(connection)
        return
    engine = make_engine()
    with engine.connect() as conn:
        _run(conn)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
