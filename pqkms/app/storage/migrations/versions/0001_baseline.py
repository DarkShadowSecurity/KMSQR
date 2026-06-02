# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""baseline: original pre-authorization schema

This snapshot reproduces the schema produced by the pre-Alembic build
(create_all + the additive _migrate ALTERs: usage_count, expires_at, and the
fork-guard UNIQUE index on audit_log.prev_hash). Databases created by that build
are STAMPED at this revision (not run) by app/storage/migrate.py; brand-new
databases RUN it from scratch. Either way, later revisions take over from here.

Revision ID: 0001
Revises:
Create Date: 2026-06-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kms_meta",
        sa.Column("k", sa.Text(), primary_key=True),
        sa.Column("v", sa.LargeBinary(), nullable=False),
    )
    op.create_table(
        "managed_keys",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
        sa.Column("key_type", sa.Text(), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
    )
    op.create_table(
        "key_versions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "key_id",
            sa.Text(),
            sa.ForeignKey("managed_keys.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("suite", sa.Integer(), nullable=False),
        sa.Column("wrapped_secret", sa.LargeBinary(), nullable=False),
        sa.Column("public_material", sa.LargeBinary()),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("usage_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.UniqueConstraint("key_id", "version", name="uq_key_versions_key_id_version"),
    )
    op.create_index("idx_key_versions_key_id", "key_versions", ["key_id"])
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text()),
        sa.Column("detail", sa.Text()),
        sa.Column("prev_hash", sa.LargeBinary(), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
    )
    # Fork guard for the hash-chain: no two entries may share a predecessor.
    op.create_index("uq_audit_prev_hash", "audit_log", ["prev_hash"], unique=True)
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("revoked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("api_tokens")
    op.drop_index("uq_audit_prev_hash", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("idx_key_versions_key_id", table_name="key_versions")
    op.drop_table("key_versions")
    op.drop_table("managed_keys")
    op.drop_table("kms_meta")
