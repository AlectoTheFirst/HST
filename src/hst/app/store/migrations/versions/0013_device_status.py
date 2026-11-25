"""device_status: the state of the last collection attempt per device

`host` is the host of a device row or the `config.host` of a source with no
device rows.

The collector compares the hash of a fetch with `last_raw_sha`.

`last_full_at` is the time of the last full normalize and load.

Revision ID: 0013
Revises: 0012
"""

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_status",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column(
            "source",
            sa.Text,
            sa.ForeignKey("sources.name", ondelete="CASCADE", onupdate="CASCADE"),
            nullable=False,
        ),
        sa.Column("host", sa.Text, nullable=False),
        sa.Column("last_raw_sha", sa.Text, nullable=False, server_default=""),
        sa.Column("last_attempt_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_full_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text, nullable=False, server_default=""),
        sa.Column("fetch_ms", sa.Integer, nullable=True),
        sa.Column("normalize_ms", sa.Integer, nullable=True),
        sa.Column("load_ms", sa.Integer, nullable=True),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "host", name="uq_device_status_source_host"),
    )
    op.create_index("ix_device_status_source", "device_status", ["source"])


def downgrade() -> None:
    op.drop_index("ix_device_status_source", table_name="device_status")
    op.drop_table("device_status")
