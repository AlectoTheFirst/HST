"""Drop the config overrides of a device row.

Revision ID: 0022
Revises: 0021

The settings of a device are the settings of its group. A device that needs
another credential, timeout, jump host or routing scope belongs in its own
group.

A device row holds the host, the port, the enabled flag and the pinned SSH host
key.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("devices", "overrides")


def downgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("overrides", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
