"""Tokenized analysis cache leases.

Revision ID: 0025
Revises: 0024
"""

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_cache_leases",
        sa.Column("lease_token", sa.String(48), primary_key=True),
        sa.Column(
            "cache_key",
            sa.String(64),
            sa.ForeignKey("analysis_cache_artifacts.cache_key", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("analysis_cache_lease_expiry", "analysis_cache_leases", ["cache_key", "expires_at"])


def downgrade() -> None:
    op.drop_index("analysis_cache_lease_expiry", table_name="analysis_cache_leases")
    op.drop_table("analysis_cache_leases")
