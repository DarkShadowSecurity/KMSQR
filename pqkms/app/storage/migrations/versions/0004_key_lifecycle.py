# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""key lifecycle: state, scheduled deletion, origin

Adds managed_keys.state (enabled|disabled|pending_deletion), deletion_at (when a
pending key becomes destroyable), and origin (generated|imported). Existing keys
are backfilled to enabled/generated. Behaviour is unchanged for enabled keys.

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("managed_keys", sa.Column("state", sa.Text(), nullable=False, server_default="enabled"))
    op.add_column("managed_keys", sa.Column("deletion_at", sa.Text()))
    op.add_column("managed_keys", sa.Column("origin", sa.Text(), nullable=False, server_default="generated"))


def downgrade() -> None:
    with op.batch_alter_table("managed_keys") as batch_op:
        batch_op.drop_column("origin")
        batch_op.drop_column("deletion_at")
        batch_op.drop_column("state")
