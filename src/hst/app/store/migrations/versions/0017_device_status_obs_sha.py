"""device_status.last_obs_sha: the observation-level change key

`last_obs_sha` holds the result of `obs_sha` in collectors/base.py.

Revision ID: 0017
Revises: 0016
"""

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_status",
        sa.Column("last_obs_sha", sa.Text, nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("device_status", "last_obs_sha")
