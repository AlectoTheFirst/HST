"""personal_access_tokens

A personal access token is the bearer credential of the MCP HTTP transport at
/api/mcp. A token belongs to one user and is deleted with that user (ON DELETE
CASCADE). The table stores only the SHA-256 hash of the token, as for sessions.
`scope` is `read` or `read-write`. It is set when the token is created, and no
statement changes it. Revoking a token deletes its row.

Revision ID: 0034
Revises: 0033
"""

import sqlalchemy as sa
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "personal_access_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("token_hash", sa.Text, nullable=False),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("scope", sa.Text, nullable=False, server_default="read"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_personal_access_tokens_token_hash"),
        sa.CheckConstraint("scope IN ('read', 'read-write')", name="ck_personal_access_tokens_scope"),
    )
    op.create_index("ix_personal_access_tokens_user", "personal_access_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_personal_access_tokens_user", table_name="personal_access_tokens")
    op.drop_table("personal_access_tokens")
