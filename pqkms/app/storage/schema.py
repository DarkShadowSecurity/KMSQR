# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
SQLAlchemy Core table definitions.

These mirror the original hand-written SQLite schema but are dialect-neutral, so
the same definitions create the schema on SQLite (dev / single-node) and
PostgreSQL (HA). LargeBinary maps to BLOB on SQLite and BYTEA on PostgreSQL;
the autoincrement integer primary keys map to AUTOINCREMENT / IDENTITY
respectively. No ORM — just metadata the repository compiles queries against.
"""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()

# A principal is a stable identity that performs actions: a machine/service or a
# human operator. API tokens are credentials *of* a principal (a service may
# rotate through several tokens over its lifetime). Auditing the principal id —
# rather than an anonymous "token[scopes]" string — is what makes actions
# attributable to a real actor, a baseline enterprise/compliance requirement.
principals = Table(
    "principals",
    metadata,
    Column("id", Text, primary_key=True),
    Column("ptype", Text, nullable=False),  # 'service' | 'human'
    Column("display_name", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("disabled", Integer, nullable=False, default=0),
)

kms_meta = Table(
    "kms_meta",
    metadata,
    Column("k", Text, primary_key=True),
    Column("v", LargeBinary, nullable=False),
)

managed_keys = Table(
    "managed_keys",
    metadata,
    Column("id", Text, primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("key_type", Text, nullable=False),  # 'aead' | 'kem' | 'sig'
    Column("current_version", Integer, nullable=False, default=1),
    Column("created_at", Text, nullable=False),
    Column("description", Text),
)

key_versions = Table(
    "key_versions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("key_id", Text, ForeignKey("managed_keys.id", ondelete="CASCADE"), nullable=False),
    Column("version", Integer, nullable=False),
    Column("suite", Integer, nullable=False),
    Column("wrapped_secret", LargeBinary, nullable=False),  # AEAD-encrypted under Root KEK
    Column("public_material", LargeBinary),                 # NULL for symmetric keys
    Column("created_at", Text, nullable=False),
    Column("state", Text, nullable=False, default="active"),  # 'active'|'rotated'|'revoked'
    # 64-bit: the AES-GCM nonce budget hard limit is 2**32, which overflows a
    # 32-bit INTEGER on PostgreSQL. BigInteger maps to BIGINT (PG) / INTEGER (SQLite).
    Column("usage_count", BigInteger, nullable=False, default=0),
    UniqueConstraint("key_id", "version", name="uq_key_versions_key_id_version"),
    Index("idx_key_versions_key_id", "key_id"),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("ts", Text, nullable=False),
    Column("actor", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("target", Text),
    Column("detail", Text),
    Column("prev_hash", LargeBinary, nullable=False),
    Column("entry_hash", LargeBinary, nullable=False),
    Column("signature", LargeBinary, nullable=False),
)

api_tokens = Table(
    "api_tokens",
    metadata,
    Column("id", Text, primary_key=True),
    Column("token_hash", LargeBinary, nullable=False),
    Column("name", Text, nullable=False),
    Column("scopes", Text, nullable=False),  # csv of scopes
    Column("created_at", Text, nullable=False),
    Column("revoked", Integer, nullable=False, default=0),
    Column("expires_at", Text),  # ISO8601 UTC; NULL = non-expiring
    # The principal this token authenticates as (principals.id). No DB-level FK:
    # the column is added by an ALTER on existing api_tokens and integrity is
    # maintained in the repository (see delete_principal). Nullable for rows
    # created by builds predating principals; the migration backfills one
    # principal per legacy token so attribution works retroactively.
    Column("principal_id", Text),
)
