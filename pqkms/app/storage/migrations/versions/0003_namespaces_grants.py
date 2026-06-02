# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""namespaces + grants: tenant isolation and per-resource authorization

Adds:
  * namespaces (key-rings) with an auto-created 'default' namespace;
  * managed_keys.namespace_id, backfilled so every existing key lands in
    'default' (new keys always set it explicitly);
  * grants (principal x resource -> operations) for strict authorization.

Behaviour is unchanged until PQKMS_AUTHZ_MODE=strict is set; this revision only
introduces the data model.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-02
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

DEFAULT_NAMESPACE_NAME = "default"


def upgrade() -> None:
    op.create_table(
        "namespaces",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
    )
    op.create_table(
        "grants",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("operations", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Text()),
        sa.UniqueConstraint("principal_id", "resource_type", "resource_id", name="uq_grants_principal_resource"),
    )
    op.create_index("idx_grants_principal", "grants", ["principal_id"])

    op.add_column("managed_keys", sa.Column("namespace_id", sa.Text(), nullable=True))

    # Create the default namespace and move every pre-existing key into it.
    bind = op.get_bind()
    default_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    bind.execute(
        sa.text(
            "INSERT INTO namespaces (id, name, created_at, description) "
            "VALUES (:id, :name, :created_at, :description)"
        ),
        {"id": default_id, "name": DEFAULT_NAMESPACE_NAME, "created_at": now,
         "description": "Default key-ring; holds keys created before namespaces existed."},
    )
    bind.execute(
        sa.text("UPDATE managed_keys SET namespace_id = :ns WHERE namespace_id IS NULL"),
        {"ns": default_id},
    )


def downgrade() -> None:
    with op.batch_alter_table("managed_keys") as batch_op:
        batch_op.drop_column("namespace_id")
    op.drop_index("idx_grants_principal", table_name="grants")
    op.drop_table("grants")
    op.drop_table("namespaces")
