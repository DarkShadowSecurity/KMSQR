# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Repository: the single storage seam for the KMS.

Every persistence operation goes through one of these methods; no other module
issues SQL. Multi-statement operations (create_key, rotate, audit append) run
inside a single transaction via engine.begin(), which fixes the partial-write
hazard the old autocommit code had. The same methods work on SQLite and
PostgreSQL because they are built from dialect-neutral SQLAlchemy Core
expressions.

Methods that read rows return plain dicts (or lists of dicts), so callers stay
decoupled from SQLAlchemy Row objects. Binary columns are normalized to `bytes`
at this boundary (psycopg may hand back memoryview for BYTEA).
"""
from __future__ import annotations

from typing import Callable, Optional

from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from .engine import make_engine
from .schema import api_tokens, audit_log, key_versions, kms_meta, managed_keys, metadata

# Fixed key for the PostgreSQL advisory lock that serializes audit appends across
# replicas. Arbitrary but stable 63-bit constant ("pqkms-audit" mod 2^63-ish).
_AUDIT_LOCK_KEY = 0x70716B6D7341756  # noqa: N816


def _b(v) -> Optional[bytes]:
    return bytes(v) if v is not None else None


class Repository:
    def __init__(self, engine: Engine):
        self._engine = engine
        metadata.create_all(engine)
        self._migrate()

    @property
    def engine(self) -> Engine:
        """Escape hatch for tooling/tests that need raw access. Not used by app code."""
        return self._engine

    def _migrate(self) -> None:
        """Additive, idempotent migrations for databases created by older builds.
        create_all() never alters an existing table, so columns added after first
        deploy are applied here."""
        from sqlalchemy import inspect

        insp = inspect(self._engine)
        tables = set(insp.get_table_names())
        stmts: list[str] = []
        if "key_versions" in tables:
            cols = {c["name"] for c in insp.get_columns("key_versions")}
            if "usage_count" not in cols:
                stmts.append("ALTER TABLE key_versions ADD COLUMN usage_count BIGINT NOT NULL DEFAULT 0")
        if "api_tokens" in tables:
            cols = {c["name"] for c in insp.get_columns("api_tokens")}
            if "expires_at" not in cols:
                stmts.append("ALTER TABLE api_tokens ADD COLUMN expires_at TEXT")
        # Fork guard for the audit hash-chain: two entries can never claim the
        # same predecessor. A UNIQUE INDEX (rather than a table constraint) is
        # addable to pre-existing tables and works on both SQLite and Postgres.
        stmts.append("CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_prev_hash ON audit_log (prev_hash)")
        if stmts:
            with self._engine.begin() as conn:
                for s in stmts:
                    conn.execute(text(s))

    # ---------------------------------------------------------------- meta ----

    def get_meta(self, k: str) -> Optional[bytes]:
        with self._engine.connect() as conn:
            row = conn.execute(select(kms_meta.c.v).where(kms_meta.c.k == k)).fetchone()
            return _b(row[0]) if row else None

    def put_meta(self, k: str, v: bytes, *, if_absent: bool = False) -> bool:
        """Insert a meta row. With if_absent=True, returns False (instead of
        raising) if the key already exists — used to make one-time boot writes
        race-safe across replicas."""
        try:
            with self._engine.begin() as conn:
                conn.execute(insert(kms_meta).values(k=k, v=v))
            return True
        except IntegrityError:
            if if_absent:
                return False
            raise

    def set_meta(self, k: str, v: bytes) -> None:
        """Upsert a meta value (update if present, else insert). Used to re-seal
        the custody envelope during operator passphrase / Root-KEK custody rotation."""
        with self._engine.begin() as conn:
            res = conn.execute(update(kms_meta).where(kms_meta.c.k == k).values(v=v))
            if res.rowcount == 0:
                conn.execute(insert(kms_meta).values(k=k, v=v))

    def meta_exists_any(self, keys: list[str]) -> bool:
        with self._engine.connect() as conn:
            return conn.execute(
                select(kms_meta.c.k).where(kms_meta.c.k.in_(keys)).limit(1)
            ).fetchone() is not None

    # -------------------------------------------------------- managed keys ----

    def create_key_with_version(self, mk: dict, kv: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(insert(managed_keys).values(**mk))
            conn.execute(insert(key_versions).values(**kv))

    def rotate_key(self, key_id: str, old_version: int, kv: dict, new_version: int) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                update(key_versions)
                .where(key_versions.c.key_id == key_id, key_versions.c.version == old_version)
                .values(state="rotated")
            )
            conn.execute(insert(key_versions).values(**kv))
            conn.execute(
                update(managed_keys).where(managed_keys.c.id == key_id).values(current_version=new_version)
            )

    _CURRENT_COLS = (
        managed_keys.c.id,
        managed_keys.c.name,
        managed_keys.c.key_type,
        managed_keys.c.current_version,
        managed_keys.c.created_at,
        managed_keys.c.description,
        key_versions.c.suite,
        key_versions.c.public_material,
    )

    def _current_join(self):
        return managed_keys.join(
            key_versions,
            (key_versions.c.key_id == managed_keys.c.id)
            & (key_versions.c.version == managed_keys.c.current_version),
        )

    def get_key_current(self, key_id: str) -> Optional[dict]:
        stmt = select(*self._CURRENT_COLS).select_from(self._current_join()).where(managed_keys.c.id == key_id)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).mappings().fetchone()
        if row is None:
            return None
        d = dict(row)
        d["public_material"] = _b(d["public_material"])
        return d

    def list_keys_current(self) -> list[dict]:
        stmt = (
            select(*self._CURRENT_COLS)
            .select_from(self._current_join())
            .order_by(managed_keys.c.created_at.desc())
        )
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).mappings().fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["public_material"] = _b(d["public_material"])
            out.append(d)
        return out

    def get_version(self, key_id: str, version: int) -> Optional[dict]:
        stmt = select(
            key_versions.c.suite, key_versions.c.wrapped_secret, key_versions.c.public_material
        ).where(key_versions.c.key_id == key_id, key_versions.c.version == version)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).mappings().fetchone()
        if row is None:
            return None
        return {
            "suite": row["suite"],
            "wrapped_secret": _b(row["wrapped_secret"]),
            "public_material": _b(row["public_material"]),
        }

    def increment_usage_if_below(self, key_id: str, version: int, hard_limit: int) -> Optional[int]:
        """Atomic counter bump used by the nonce budget. Returns the new count,
        or None if no row matched (version missing OR already at the hard cap)."""
        with self._engine.begin() as conn:
            row = conn.execute(
                update(key_versions)
                .where(
                    key_versions.c.key_id == key_id,
                    key_versions.c.version == version,
                    key_versions.c.usage_count < hard_limit,
                )
                .values(usage_count=key_versions.c.usage_count + 1)
                .returning(key_versions.c.usage_count)
            ).fetchone()
        return row[0] if row else None

    def version_exists(self, key_id: str, version: int) -> bool:
        with self._engine.connect() as conn:
            return conn.execute(
                select(key_versions.c.id).where(
                    key_versions.c.key_id == key_id, key_versions.c.version == version
                )
            ).fetchone() is not None

    # --------------------------------------------------------------- audit ----

    def append_audit(self, build: Callable[[bytes], dict], *, max_retries: int = 8) -> int:
        """Append one audit entry atomically and HA-safely.

        Within a single transaction: read the last entry_hash, let the caller
        build the row (hash-chain link + signature) from it, and insert. On
        PostgreSQL a transaction-scoped advisory lock serializes appends across
        replicas. The UNIQUE(prev_hash) index is the hard guarantee on every
        backend: a losing concurrent appender hits an IntegrityError, and we
        retry from the new chain head rather than fork."""
        is_pg = self._engine.dialect.name == "postgresql"
        for attempt in range(max_retries):
            try:
                with self._engine.begin() as conn:
                    if is_pg:
                        conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
                    last = conn.execute(
                        select(audit_log.c.entry_hash).order_by(audit_log.c.seq.desc()).limit(1)
                    ).fetchone()
                    prev_hash = _b(last[0]) if last else b"\x00" * 32
                    row = build(prev_hash)
                    seq = conn.execute(
                        insert(audit_log).values(**row).returning(audit_log.c.seq)
                    ).scalar_one()
                return seq
            except IntegrityError:
                # A concurrent appender took this prev_hash slot; rebuild from the
                # new head and retry. Re-raise if we exhaust the retry budget.
                if attempt == max_retries - 1:
                    raise
        raise RuntimeError("unreachable")

    _AUDIT_FULL = (
        audit_log.c.seq,
        audit_log.c.ts,
        audit_log.c.actor,
        audit_log.c.action,
        audit_log.c.target,
        audit_log.c.detail,
        audit_log.c.prev_hash,
        audit_log.c.entry_hash,
        audit_log.c.signature,
    )

    def iter_audit_asc(self) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(*self._AUDIT_FULL).order_by(audit_log.c.seq.asc())).mappings().fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["prev_hash"] = _b(d["prev_hash"])
            d["entry_hash"] = _b(d["entry_hash"])
            d["signature"] = _b(d["signature"])
            out.append(d)
        return out

    def list_audit_desc(self, limit: int) -> list[dict]:
        cols = (
            audit_log.c.seq, audit_log.c.ts, audit_log.c.actor,
            audit_log.c.action, audit_log.c.target, audit_log.c.detail,
        )
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*cols).order_by(audit_log.c.seq.desc()).limit(limit)
            ).mappings().fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- tokens ----

    def has_any_token(self) -> bool:
        with self._engine.connect() as conn:
            return conn.execute(
                select(api_tokens.c.id).where(api_tokens.c.revoked == 0).limit(1)
            ).fetchone() is not None

    def insert_token(self, row: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(insert(api_tokens).values(**row))

    def revoke_token(self, token_id: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(update(api_tokens).where(api_tokens.c.id == token_id).values(revoked=1))

    def list_tokens(self) -> list[dict]:
        cols = (
            api_tokens.c.id, api_tokens.c.name, api_tokens.c.scopes,
            api_tokens.c.created_at, api_tokens.c.revoked, api_tokens.c.expires_at,
        )
        with self._engine.connect() as conn:
            rows = conn.execute(select(*cols).order_by(api_tokens.c.created_at.desc())).mappings().fetchall()
        return [dict(r) for r in rows]

    def find_active_tokens_by_id_prefix(self, prefix: str) -> list[dict]:
        cols = (api_tokens.c.token_hash, api_tokens.c.scopes, api_tokens.c.expires_at)
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*cols).where(api_tokens.c.revoked == 0, api_tokens.c.id.like(prefix + "%"))
            ).mappings().fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["token_hash"] = _b(d["token_hash"])
            out.append(d)
        return out

    # --------------------------------------------------------------- admin ----

    def ping(self) -> bool:
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def checkpoint(self) -> None:
        """Flush the SQLite WAL into the main db file. No-op on other backends."""
        if self._engine.dialect.name != "sqlite":
            return
        try:
            with self._engine.begin() as conn:
                conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
        except Exception:
            pass


def make_repository(url: str | None = None, *, data_dir: str | None = None) -> Repository:
    return Repository(make_engine(url, data_dir=data_dir))
