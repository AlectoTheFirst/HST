"""evidence_exports: one row per download of decrypted evidence

A debug bundle or an HTTP trace holds decrypted collection evidence, and a full
bundle holds the credentials that the redacted mode removes. Each download
writes one row with the account that asked. `user_id` is ON DELETE SET NULL,
and the row keeps `username` after the account is removed. The rows are not
purged.

Revision ID: 0036
Revises: 0035
"""

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_exports",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("username", sa.Text, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("raw_mode", sa.Text, nullable=True),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("host", sa.Text, nullable=False, server_default=""),
        sa.Column("run_id", sa.Text, nullable=False),
        sa.Column("payloads", sa.Integer, nullable=False, server_default="1"),
    )
    op.create_index("ix_evidence_exports_at", "evidence_exports", ["at"])


def downgrade() -> None:
    op.drop_index("ix_evidence_exports_at", table_name="evidence_exports")
    op.drop_table("evidence_exports")
