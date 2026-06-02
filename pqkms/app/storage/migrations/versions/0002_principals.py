# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""principals: attributable identities for tokens and audit

Adds the principals table and api_tokens.principal_id, then backfills: every
pre-existing token gets its own service principal (named after the token) and is
linked to it, so audit attribution works retroactively for databases that
predate this change.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-02
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "principals",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("ptype", sa.Text(), nullable=False),  # 'service' | 'human'
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("disabled", sa.Integer(), nullable=False, server_default="0"),
    )
    # Plain nullable column (no DB-level FK): adding it is a cheap metadata-only
    # ALTER on both SQLite and PostgreSQL — no table rewrite of api_tokens, which
    # may hold live credentials. Referential integrity is maintained in the
    # repository layer (principal delete cascades there).
    op.add_column("api_tokens", sa.Column("principal_id", sa.Text(), nullable=True))

    # Backfill: one service principal per existing token. No-op on a fresh DB.
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, name, created_at FROM api_tokens")).fetchall()
    for tid, name, created_at in rows:
        pid = str(uuid.uuid4())
        bind.execute(
            sa.text(
                "INSERT INTO principals (id, ptype, display_name, created_at, disabled) "
                "VALUES (:id, :ptype, :display_name, :created_at, 0)"
            ),
            {"id": pid, "ptype": "service", "display_name": name or "legacy-token", "created_at": created_at},
        )
        bind.execute(
            sa.text("UPDATE api_tokens SET principal_id = :pid WHERE id = :tid"),
            {"pid": pid, "tid": tid},
        )


def downgrade() -> None:
    with op.batch_alter_table("api_tokens") as batch_op:
        batch_op.drop_column("principal_id")
    op.drop_table("principals")
