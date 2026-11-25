"""login_events: one row per authentication decision

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
        # `username` is the name that a local login presented or the name that an
        # SSO login resolved or provisioned. A failed attempt can hold the name of
        # an account that does not exist.
        sa.Column("username", sa.Text, nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("provider", sa.Text, nullable=False),  # 'local' or the provider slug
        sa.Column("outcome", sa.Text, nullable=False),  # short stable token, e.g. 'ok', 'bad_credentials'
        sa.Column("source", sa.Text, nullable=False, server_default=""),
    )
    op.create_index("ix_login_events_at", "login_events", ["at"])


def downgrade() -> None:
    op.drop_index("ix_login_events_at", table_name="login_events")
    op.drop_table("login_events")
