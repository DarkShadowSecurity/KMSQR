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

from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from .engine import make_engine
from .migrate import run_migrations
from .schema import (
    api_tokens,
    audit_log,
    grants,
    key_versions,
    kms_meta,
    managed_keys,
    namespaces,
    principals,
)

# Fixed key for the PostgreSQL advisory lock that serializes audit appends across
# replicas. Arbitrary but stable 63-bit constant ("pqkms-audit" mod 2^63-ish).
_AUDIT_LOCK_KEY = 0x70716B6D7341756  # noqa: N816


def _b(v) -> Optional[bytes]:
    return bytes(v) if v is not None else None


class Repository:
    def __init__(self, engine: Engine):
        self._engine = engine
        # Alembic owns the schema: bring the database to head (creating it from
        # scratch on a fresh DB, or applying only the new revisions on an
        # existing one). Replaces create_all + ad-hoc ALTERs.
        run_migrations(engine)

    @property
    def engine(self) -> Engine:
        """Escape hatch for tooling/tests that need raw access. Not used by app code."""
        return self._engine

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

    def set_key_state(self, key_id: str, state: str, deletion_at: Optional[str] = None) -> bool:
        """Update a key's lifecycle state (and its deletion_at). Returns False if
        the key does not exist."""
        with self._engine.begin() as conn:
            res = conn.execute(
                update(managed_keys).where(managed_keys.c.id == key_id).values(state=state, deletion_at=deletion_at)
            )
        return res.rowcount > 0

    def set_rotation_policy(self, key_id: str, period_days: Optional[int]) -> bool:
        with self._engine.begin() as conn:
            res = conn.execute(
                update(managed_keys).where(managed_keys.c.id == key_id)
                .values(rotation_period_days=period_days)
            )
        return res.rowcount > 0

    def list_rotation_candidates(self) -> list[dict]:
        """Enabled keys that have a rotation policy, with the current version's
        creation time. The due/not-due decision is made by the caller (date math
        kept out of SQL for dialect portability)."""
        stmt = (
            select(
                managed_keys.c.id,
                managed_keys.c.rotation_period_days,
                key_versions.c.created_at.label("version_created_at"),
            )
            .select_from(self._current_join())
            .where(
                managed_keys.c.rotation_period_days.isnot(None),
                managed_keys.c.state == "enabled",
            )
        )
        with self._engine.connect() as conn:
            return [dict(r) for r in conn.execute(stmt).mappings().fetchall()]

    def get_key_state(self, key_id: str) -> Optional[dict]:
        """Return {state, deletion_at} for a key, or None if it does not exist."""
        with self._engine.connect() as conn:
            row = conn.execute(
                select(managed_keys.c.state, managed_keys.c.deletion_at).where(managed_keys.c.id == key_id)
            ).mappings().fetchone()
        return dict(row) if row else None

    def destroy_key(self, key_id: str) -> bool:
        """Permanently delete a key: its grants, all versions (FK cascade), and
        the key row, in one transaction. Returns False if the key does not exist."""
        with self._engine.begin() as conn:
            exists = conn.execute(select(managed_keys.c.id).where(managed_keys.c.id == key_id)).fetchone()
            if not exists:
                return False
            conn.execute(
                delete(grants).where(grants.c.resource_type == "key", grants.c.resource_id == key_id)
            )
            conn.execute(delete(key_versions).where(key_versions.c.key_id == key_id))
            conn.execute(delete(managed_keys).where(managed_keys.c.id == key_id))
        return True

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
        managed_keys.c.namespace_id,
        managed_keys.c.state,
        managed_keys.c.deletion_at,
        managed_keys.c.origin,
        managed_keys.c.rotation_period_days,
        key_versions.c.suite,
        key_versions.c.public_material,
        key_versions.c.created_at.label("version_created_at"),
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

    def list_keys_current(self, *, limit: int = 200, offset: int = 0) -> list[dict]:
        stmt = (
            select(*self._CURRENT_COLS)
            .select_from(self._current_join())
            .order_by(managed_keys.c.created_at.desc(), managed_keys.c.id.asc())
            .limit(limit).offset(offset)
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

    def list_tokens(self, *, limit: int = 200, offset: int = 0) -> list[dict]:
        cols = (
            api_tokens.c.id, api_tokens.c.name, api_tokens.c.scopes,
            api_tokens.c.created_at, api_tokens.c.revoked, api_tokens.c.expires_at,
            api_tokens.c.principal_id,
        )
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*cols).order_by(api_tokens.c.created_at.desc(), api_tokens.c.id.asc())
                .limit(limit).offset(offset)
            ).mappings().fetchall()
        return [dict(r) for r in rows]

    def find_active_tokens_by_id_prefix(self, prefix: str) -> list[dict]:
        # Left join the principal so verify() can attribute the call to a real
        # identity without a second round-trip. A token's principal is disabled
        # => the token is treated as inactive (filtered out below in auth).
        j = api_tokens.outerjoin(principals, principals.c.id == api_tokens.c.principal_id)
        cols = (
            api_tokens.c.token_hash,
            api_tokens.c.scopes,
            api_tokens.c.expires_at,
            api_tokens.c.principal_id,
            principals.c.display_name,
            principals.c.disabled.label("principal_disabled"),
        )
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*cols)
                .select_from(j)
                .where(api_tokens.c.revoked == 0, api_tokens.c.id.like(prefix + "%"))
            ).mappings().fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["token_hash"] = _b(d["token_hash"])
            out.append(d)
        return out

    # ---------------------------------------------------------- principals ----

    def insert_principal(self, row: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(insert(principals).values(**row))

    def get_principal(self, principal_id: str) -> Optional[dict]:
        cols = (
            principals.c.id, principals.c.ptype, principals.c.display_name,
            principals.c.created_at, principals.c.disabled,
        )
        with self._engine.connect() as conn:
            row = conn.execute(select(*cols).where(principals.c.id == principal_id)).mappings().fetchone()
        return dict(row) if row else None

    def list_principals(self, *, limit: int = 200, offset: int = 0) -> list[dict]:
        cols = (
            principals.c.id, principals.c.ptype, principals.c.display_name,
            principals.c.created_at, principals.c.disabled,
        )
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*cols).order_by(principals.c.created_at.desc(), principals.c.id.asc())
                .limit(limit).offset(offset)
            ).mappings().fetchall()
        return [dict(r) for r in rows]

    def set_principal_disabled(self, principal_id: str, disabled: bool) -> bool:
        with self._engine.begin() as conn:
            res = conn.execute(
                update(principals).where(principals.c.id == principal_id).values(disabled=1 if disabled else 0)
            )
        return res.rowcount > 0

    def delete_principal(self, principal_id: str) -> bool:
        """Delete a principal and revoke (not delete) its tokens, so historical
        audit entries that reference the token id still resolve. Returns False if
        the principal does not exist. The two writes share one transaction so the
        principal is never removed while its tokens remain usable."""
        with self._engine.begin() as conn:
            exists = conn.execute(
                select(principals.c.id).where(principals.c.id == principal_id)
            ).fetchone()
            if not exists:
                return False
            conn.execute(
                update(api_tokens).where(api_tokens.c.principal_id == principal_id).values(revoked=1)
            )
            conn.execute(delete(principals).where(principals.c.id == principal_id))
        return True

    # --------------------------------------------------------- namespaces ----

    def insert_namespace(self, row: dict) -> None:
        with self._engine.begin() as conn:
            conn.execute(insert(namespaces).values(**row))

    _NS_COLS = (namespaces.c.id, namespaces.c.name, namespaces.c.created_at, namespaces.c.description)

    def get_namespace_by_id(self, namespace_id: str) -> Optional[dict]:
        with self._engine.connect() as conn:
            row = conn.execute(select(*self._NS_COLS).where(namespaces.c.id == namespace_id)).mappings().fetchone()
        return dict(row) if row else None

    def get_namespace_by_name(self, name: str) -> Optional[dict]:
        with self._engine.connect() as conn:
            row = conn.execute(select(*self._NS_COLS).where(namespaces.c.name == name)).mappings().fetchone()
        return dict(row) if row else None

    def list_namespaces(self) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(select(*self._NS_COLS).order_by(namespaces.c.created_at.asc())).mappings().fetchall()
        return [dict(r) for r in rows]

    def get_key_namespace(self, key_id: str) -> Optional[str]:
        """Return the namespace_id of a key, or None if the key does not exist."""
        with self._engine.connect() as conn:
            row = conn.execute(
                select(managed_keys.c.namespace_id).where(managed_keys.c.id == key_id)
            ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------- grants ----

    _GRANT_COLS = (
        grants.c.id, grants.c.principal_id, grants.c.resource_type,
        grants.c.resource_id, grants.c.operations, grants.c.created_at, grants.c.created_by,
    )

    def upsert_grant(self, row: dict) -> str:
        """Insert a grant, or replace the operations of the existing grant for the
        same (principal, resource_type, resource_id). Returns the grant id that is
        now authoritative for that triple."""
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(grants.c.id).where(
                    grants.c.principal_id == row["principal_id"],
                    grants.c.resource_type == row["resource_type"],
                    grants.c.resource_id == row["resource_id"],
                )
            ).fetchone()
            if existing:
                conn.execute(
                    update(grants).where(grants.c.id == existing[0]).values(
                        operations=row["operations"], created_at=row["created_at"], created_by=row.get("created_by"),
                    )
                )
                return existing[0]
            conn.execute(insert(grants).values(**row))
            return row["id"]

    def get_grants_for_principal(self, principal_id: str) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*self._GRANT_COLS).where(grants.c.principal_id == principal_id)
            ).mappings().fetchall()
        return [dict(r) for r in rows]

    def list_grants(self, *, limit: int = 200, offset: int = 0) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(*self._GRANT_COLS).order_by(grants.c.created_at.desc(), grants.c.id.asc())
                .limit(limit).offset(offset)
            ).mappings().fetchall()
        return [dict(r) for r in rows]

    def delete_grant(self, grant_id: str) -> bool:
        with self._engine.begin() as conn:
            res = conn.execute(delete(grants).where(grants.c.id == grant_id))
        return res.rowcount > 0

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
