"""sessions.last_used_at

A session that is unused for SESSION_IDLE_TIMEOUT_HOURS stops authenticating.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sessions",
        sa.Column(
            "last_used_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # The server default fills the existing rows. The app supplies the value on
    # every insert, and an insert without the value fails.
    op.alter_column("sessions", "last_used_at", server_default=None)


def downgrade() -> None:
    op.drop_column("sessions", "last_used_at")
