# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Engine construction.

PQKMS_DB_URL selects the backend (any SQLAlchemy URL). When unset, defaults to a
SQLite file under PQKMS_DATA_DIR so the dev/single-node quickstart needs no
database server. PostgreSQL (postgresql+psycopg://...) enables the HA topology.

SQLite connections get the pragmas the KMS depends on (WAL for concurrent
readers, foreign_keys for the key_versions cascade, busy_timeout so writers wait
rather than erroring under contention) applied on every pooled connection.
"""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


def resolve_url(url: str | None = None, *, data_dir: str | None = None) -> str:
    if url is None:
        url = os.environ.get("PQKMS_DB_URL")
    if url:
        return url
    dd = Path(data_dir or os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    dd.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(dd / 'pqkms.sqlite').as_posix()}"


def make_engine(url: str | None = None, *, data_dir: str | None = None) -> Engine:
    url = resolve_url(url, data_dir=data_dir)
    is_sqlite = url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    engine = create_engine(
        url,
        future=True,
        connect_args=connect_args,
        # pre-ping matters for long-lived server-backed pools (Postgres); it is
        # unnecessary overhead for local SQLite.
        pool_pre_ping=not is_sqlite,
    )

    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

    return engine
