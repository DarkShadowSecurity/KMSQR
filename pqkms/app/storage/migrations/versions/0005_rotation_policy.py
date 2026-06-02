# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""rotation policy: managed_keys.rotation_period_days

Adds an optional automatic-rotation period per key. NULL means manual rotation
only (unchanged behaviour); a positive integer means the key is "due" once that
many days have elapsed since its current version was created.

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("managed_keys", sa.Column("rotation_period_days", sa.Integer()))


def downgrade() -> None:
    with op.batch_alter_table("managed_keys") as batch_op:
        batch_op.drop_column("rotation_period_days")
