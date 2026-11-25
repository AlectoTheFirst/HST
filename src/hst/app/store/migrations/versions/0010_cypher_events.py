"""cypher_events: one row per Cypher call

app/routes/cypher.py caps the size of `query`.

A maintenance job deletes the rows older than CYPHER_EVENT_RETENTION_DAYS.

Revision ID: 0010
Revises: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cypher_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("query", sa.Text, nullable=False),
        # 'ok', 'rejected', 'too_large', 'result_too_large', 'error'
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("row_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("byte_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("ix_cypher_events_created_at", "cypher_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_cypher_events_created_at", table_name="cypher_events")
    op.drop_table("cypher_events")
