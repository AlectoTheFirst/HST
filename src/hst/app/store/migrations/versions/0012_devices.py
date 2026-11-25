"""devices: the devices of a source

A source with no device rows collects `config.host`.

`host_key` is the TOFU pin of the device. It is written only while it is empty.

Revision ID: 0012
Revises: 0011
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source",
            sa.Text,
            sa.ForeignKey("sources.name", ondelete="CASCADE", onupdate="CASCADE"),
            nullable=False,
        ),
        sa.Column("host", sa.Text, nullable=False),
        sa.Column("port", sa.Integer, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("overrides", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("host_key", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "host", name="uq_devices_source_host"),
    )
    op.create_index("ix_devices_source", "devices", ["source"])


def downgrade() -> None:
    op.drop_index("ix_devices_source", table_name="devices")
    op.drop_table("devices")
