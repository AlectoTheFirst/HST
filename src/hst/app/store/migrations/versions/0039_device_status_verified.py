"""device_status.last_verified_started_at and last_verified_at: the last check of a device

A per-device fetch that finds a device unchanged against the stored basis parks
nothing. The 2 columns hold the start and the end of that check. The next
device run publishes them as the time at which the carried device was last
checked (`DeviceEntry.verified_started_ms`, `verified_ms`).

Both columns are nullable. NULL means that no fetch checked the device.

Revision ID: 0039
Revises: 0038
"""

import sqlalchemy as sa
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_status",
        sa.Column("last_verified_started_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "device_status",
        sa.Column("last_verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("device_status", "last_verified_at")
    op.drop_column("device_status", "last_verified_started_at")
