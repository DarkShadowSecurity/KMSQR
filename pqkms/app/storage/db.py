# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""SQLite storage. All sensitive fields are encrypted with the Root KEK before insertion."""
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS kms_meta (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS managed_keys (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    key_type TEXT NOT NULL,            -- 'aead', 'kem', 'sig'
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS key_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    suite INTEGER NOT NULL,            -- algorithm suite id
    wrapped_secret BLOB NOT NULL,      -- private/symmetric material, AEAD-encrypted under Root KEK
    public_material BLOB,              -- public key for asymmetric keys, NULL otherwise
    created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active', -- 'active', 'rotated', 'revoked'
    UNIQUE(key_id, version),
    FOREIGN KEY(key_id) REFERENCES managed_keys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    prev_hash BLOB NOT NULL,
    entry_hash BLOB NOT NULL,
    signature BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT NOT NULL,             -- csv of scopes
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_key_versions_key_id ON key_versions(key_id);
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq);
"""


class Database:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._local = threading.local()
        # initialize
        with self._connect() as c:
            c.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def conn(self) -> sqlite3.Connection:
        return self._connect()

    def checkpoint(self) -> None:
        """Force a WAL checkpoint so all data is written to the main db file.

        Without periodic checkpoints, all writes accumulate in the WAL.
        If the process is killed without a clean shutdown, uncommitted WAL
        pages may be lost — causing decrypt failures for recently encrypted
        secrets.
        """
        try:
            self._connect().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception:
            pass
