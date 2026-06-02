# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Apply Alembic migrations on startup.

The repository calls run_migrations(engine) instead of create_all, so the schema
is always brought to head by versioned, reversible migrations — on SQLite
(quickstart) and PostgreSQL (HA) alike.

Three cases are handled transparently:
  * Fresh database (no tables): run every migration from base to head.
  * Pre-Alembic database (original tables present, no alembic_version): its
    schema already matches revision 0001, so we STAMP it there, then upgrade.
  * Already managed by Alembic: upgrade to head (a no-op once current).

The app's own Connection is shared with Alembic so migrations run on the same
engine/URL the app uses — essential for the SQLite quickstart and for tests that
point at a temporary database file.
"""
from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

log = logging.getLogger("pqkms.migrate")

_MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_BASELINE_REVISION = "0001"
# Transaction-scoped advisory lock so that, when several replicas boot at once
# during a rolling upgrade, only one applies migrations and the rest block until
# it commits (then find the schema already at head and no-op). Distinct from the
# audit-append lock key. Released automatically at transaction end.
_MIGRATION_LOCK_KEY = 0x70716B6D734D6967  # noqa: N816


def _config(connection) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    # Hand Alembic the live connection so env.py runs migrations on this engine.
    cfg.attributes["connection"] = connection
    return cfg


def run_migrations(engine: Engine) -> None:
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            # Serialize concurrent migrators across replicas. Held until this
            # transaction commits, covering both the stamp and the upgrade below.
            connection.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _MIGRATION_LOCK_KEY})
        tables = set(inspect(connection).get_table_names())
        cfg = _config(connection)
        if "alembic_version" not in tables and "managed_keys" in tables:
            # Database created by a pre-Alembic build: its schema already equals
            # revision 0001. Record that fact (without re-running the baseline
            # DDL) so the upgrade applies only the newer revisions.
            command.stamp(cfg, _BASELINE_REVISION)
            log.info("stamped existing database at baseline revision %s", _BASELINE_REVISION)
        command.upgrade(cfg, "head")
    log.info("database schema is at head")
