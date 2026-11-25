"""Typed site defaults and target-to-discovered-device provenance.

Revision ID: 0018
Revises: 0017
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sites", sa.Column("params", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")))
    # The site codes of the existing sources become Site rows. The statement
    # changes no source row and no UID assignment.
    op.execute(
        """
        INSERT INTO sites (code, name, location, params, created_at, updated_at)
        SELECT DISTINCT config->>'site_code', '', '', '{}'::jsonb, now(), now()
        FROM sources
        WHERE coalesce(config->>'site_code', '') <> ''
        ON CONFLICT (code) DO NOTHING
        """
    )
    op.create_table(
        "target_devices",
        sa.Column("source", sa.Text, sa.ForeignKey("sources.name", ondelete="CASCADE"), primary_key=True),
        sa.Column("host", sa.Text, primary_key=True),
        sa.Column("device_uid", sa.Text, primary_key=True),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )
    op.create_index("ix_target_devices_uid", "target_devices", ["device_uid"])


def downgrade() -> None:
    op.drop_table("target_devices")
    op.drop_column("sites", "params")
